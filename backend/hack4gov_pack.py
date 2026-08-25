from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import io
import json
import math
import os
import re
import shutil
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend import challenge_pack as base
from backend import main as core
from backend import workbench as wb

try:
    from PIL import Image, ImageChops
except Exception:  # Pillow is installed in the Docker image, but keep import-safe.
    Image = None
    ImageChops = None


# challenge_pack already patched the original workbench. Extend that layer.
BASE_CATALOG = wb.analysis_catalog
BASE_EXECUTE = wb.execute_analysis

MAX_LIBRARY_FILES = int(os.getenv("CTF_LIBRARY_MAX_FILES", "500"))
MAX_LIBRARY_BYTES = int(os.getenv("CTF_LIBRARY_MAX_BYTES", str(1024 * 1024 * 1024)))
MAX_INLINE_OBJECTS = int(os.getenv("CTF_INLINE_OBJECTS", "40"))


def read_prefix(row, limit: int = 4096) -> bytes:
    with Path(row["path"]).open("rb") as f:
        return f.read(limit)


def repair_kinds(row) -> list[str]:
    try:
        head = read_prefix(row, 4096)
    except OSError:
        return []

    kinds: list[str] = []
    if len(head) >= 16 and head[4:8] == b"\r\n\x1a\n" and head[12:16] == b"IHDR" and not head.startswith(b"\x89PNG\r\n\x1a\n"):
        kinds.append("PNG signature")
    if len(head) >= 12 and head[8:12] == b"WAVE" and not head.startswith(b"RIFF"):
        kinds.append("RIFF/WAV header")
    if len(head) >= 12 and (head[6:10] in {b"JFIF", b"Exif"}) and not head.startswith(b"\xff\xd8"):
        kinds.append("JPEG SOI")
    for sig, label in ((b"%PDF-", "PDF carve"), (b"PK\x03\x04", "ZIP carve"), (b"MZ", "PE carve")):
        pos = head.find(sig)
        if 0 < pos <= 2048:
            kinds.append(label)
    return kinds


async def repair_header_analysis(conn, row, analysis_id: str, label: str):
    path = Path(row["path"])
    if row["size"] > core.MAX_EXTRACTED:
        output = "Artifact is larger than the configured extraction limit; repair was skipped."
        run_id = wb.record_run(conn, row["id"], analysis_id, label, ["python", "<repair-header>"], output, 1, "error")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "error", "output": output}

    data = path.read_bytes()
    children: list[str] = []
    notes: list[str] = []
    pipeline = core.Pipeline(conn)

    if len(data) >= 16 and data[4:8] == b"\r\n\x1a\n" and data[12:16] == b"IHDR" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        fixed = b"\x89PNG\r\n\x1a\n" + data[8:]
        child = pipeline.process(fixed, f"repaired_{Path(row['filename']).stem}.png", parent=row["id"], origin="derived", technique="Repair corrupted PNG signature", depth=1)
        children.append(child)
        notes.append(f"Repaired PNG signature -> {child}")

    if len(data) >= 12 and data[8:12] == b"WAVE" and not data.startswith(b"RIFF"):
        fixed = b"RIFF" + data[4:]
        child = pipeline.process(fixed, f"repaired_{Path(row['filename']).stem}.wav", parent=row["id"], origin="derived", technique="Repair RIFF/WAV header", depth=1)
        children.append(child)
        notes.append(f"Repaired RIFF/WAV header -> {child}")

    if len(data) >= 12 and data[6:10] in {b"JFIF", b"Exif"} and not data.startswith(b"\xff\xd8"):
        fixed = b"\xff\xd8" + data[2:]
        child = pipeline.process(fixed, f"repaired_{Path(row['filename']).stem}.jpg", parent=row["id"], origin="derived", technique="Repair JPEG SOI", depth=1)
        children.append(child)
        notes.append(f"Repaired JPEG SOI -> {child}")

    for sig, extension, technique in (
        (b"%PDF-", ".pdf", "Carve PDF from prepended data"),
        (b"PK\x03\x04", ".zip", "Carve ZIP from prepended data"),
        (b"MZ", ".exe", "Carve PE from prepended data"),
    ):
        pos = data[:4096].find(sig)
        if 0 < pos <= 2048:
            carved = data[pos:]
            child = pipeline.process(carved, f"carved_{pos:08x}{extension}", parent=row["id"], origin="derived", technique=technique, depth=1)
            children.append(child)
            notes.append(f"{technique} at 0x{pos:X} -> {child}")

    output = "\n".join(notes) if notes else "No supported header repair was applicable."
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, ["python", "<repair-header>"], output, 0, "complete")
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "complete", "output": output, "artifacts": children, "flags": found}


DATA_URI_RE = re.compile(rb"data:([A-Za-z0-9.+_-]+/[A-Za-z0-9.+_-]+);base64,([A-Za-z0-9+/=]+)")
MIME_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/svg+xml": ".svg",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
}


async def embedded_data_analysis(conn, row, analysis_id: str, label: str):
    data = Path(row["path"]).read_bytes()
    pipeline = core.Pipeline(conn)
    children: list[str] = []
    notes: list[str] = []

    for index, match in enumerate(DATA_URI_RE.finditer(data), 1):
        if index > MAX_INLINE_OBJECTS:
            break
        mime = match.group(1).decode("ascii", errors="replace").lower()
        try:
            decoded = base64.b64decode(match.group(2), validate=False)
        except Exception:
            continue
        if not decoded or len(decoded) > core.MAX_EXTRACTED:
            continue
        ext = MIME_EXT.get(mime, ".bin")
        name = f"embedded_data_{index:03d}{ext}"
        child = pipeline.process(decoded, name, parent=row["id"], origin="derived", technique=f"Embedded data URI extraction ({mime})", depth=1)
        children.append(child)
        notes.append(f"{index}. {mime} · {len(decoded):,} bytes -> {child}")

    output = f"Extracted {len(children)} embedded data URI object(s)."
    if notes:
        output += "\n" + "\n".join(notes)
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, ["python", "<extract-data-uri>"], output, 0, "complete")
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "complete", "output": output, "artifacts": children, "flags": found}


async def qr_analysis(conn, row, analysis_id: str, label: str):
    tool = shutil.which("zbarimg")
    argv = [tool or "zbarimg", "--quiet", "--raw", str(Path(row["path"]))]
    if not tool:
        output = "zbarimg is not installed in the analysis container."
        run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}
    rc, output, status = await asyncio.to_thread(wb.run_process, argv, Path(row["path"]).parent, 20)
    if not output.strip() and rc != 0:
        output = "No QR/barcode payload decoded."
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, output, rc, status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": status, "returncode": rc, "output": output, "flags": found}


def csv_coordinate_report(row) -> str:
    raw = Path(row["path"]).read_text(encoding="utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    if not reader.fieldnames:
        return "CSV has no header row."

    canonical = {name.strip().lower(): name for name in reader.fieldnames if name}
    lat_key = next((canonical[x] for x in ("latitude", "lat") if x in canonical), None)
    lon_key = next((canonical[x] for x in ("longitude", "lon", "lng", "long") if x in canonical), None)
    id_key = next((canonical[x] for x in ("id", "coordinateid", "coordinate_id", "label", "name") if x in canonical), None)
    if not lat_key or not lon_key:
        return f"No Latitude/Longitude columns found. Columns: {', '.join(reader.fieldnames)}"

    points: list[tuple[str, float, float]] = []
    for index, item in enumerate(reader, 1):
        try:
            lat = float(item.get(lat_key, ""))
            lon = float(item.get(lon_key, ""))
        except (TypeError, ValueError):
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        label = str(item.get(id_key, "")).strip() if id_key else ""
        points.append((label or f"row{index}", lat, lon))
        if len(points) >= 3000:
            break

    if len(points) < 2:
        return "Fewer than two valid coordinate rows were detected."

    def haversine(a, b):
        _, lat1, lon1 = a
        _, lat2, lon2 = b
        radius = 6371.0088
        p1, p2 = math.radians(lat1), math.radians(lat2)
        dp = math.radians(lat2 - lat1)
        dl = math.radians(lon2 - lon1)
        h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
        return 2 * radius * math.asin(math.sqrt(h))

    closest = None
    farthest = None
    for i in range(len(points) - 1):
        a = points[i]
        for j in range(i + 1, len(points)):
            b = points[j]
            distance = haversine(a, b)
            item = (distance, a, b)
            if closest is None or distance < closest[0]:
                closest = item
            if farthest is None or distance > farthest[0]:
                farthest = item

    assert closest and farthest
    pair_expression = f"{closest[1][0]}-{closest[2][0]},{farthest[1][0]}-{farthest[2][0]}"
    return "\n".join([
        f"Rows analyzed: {len(points)}",
        f"ID column: {id_key or '(row number)'}",
        f"Closest pair: {closest[1][0]} <-> {closest[2][0]} = {closest[0]:.6f} km",
        f"Farthest pair: {farthest[1][0]} <-> {farthest[2][0]} = {farthest[0]:.6f} km",
        f"Pair expression: {pair_expression}",
    ])


async def csv_coordinate_analysis(conn, row, analysis_id: str, label: str):
    try:
        output = csv_coordinate_report(row)
        status, rc = "complete", 0
    except Exception as exc:
        output = f"{type(exc).__name__}: {exc}"
        status, rc = "error", 1
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, ["python", "<csv-coordinate-solver>"], output, rc, status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": status, "output": output, "flags": found}


_TSHARK_FIELDS: set[str] | None = None


def tshark_fields() -> set[str]:
    global _TSHARK_FIELDS
    if _TSHARK_FIELDS is not None:
        return _TSHARK_FIELDS
    tool = shutil.which("tshark")
    if not tool:
        _TSHARK_FIELDS = set()
        return _TSHARK_FIELDS
    rc, output, _ = wb.run_process([tool, "-G", "fields"], timeout=25)
    fields: set[str] = set()
    if rc == 0:
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] == "F":
                fields.add(parts[2])
    _TSHARK_FIELDS = fields
    return fields


def printable_from_hex_tokens(text: str) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for token in re.findall(r"(?i)(?:[0-9a-f]{2}:){3,}[0-9a-f]{2}|\b[0-9a-f]{12,}\b", text):
        clean = token.replace(":", "")
        if len(clean) % 2:
            continue
        try:
            raw = bytes.fromhex(clean)
        except ValueError:
            continue
        rendered = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
        printable = sum(32 <= b <= 126 or b in {9, 10, 13} for b in raw) / max(1, len(raw))
        if printable >= 0.55 and rendered not in seen:
            seen.add(rendered)
            results.append(rendered[:2000])
        if len(results) >= 100:
            break
    return results


async def pcap_fragment_analysis(conn, row, analysis_id: str, label: str):
    tool = shutil.which("tshark")
    if not tool:
        output = "tshark is not installed."
        run_id = wb.record_run(conn, row["id"], analysis_id, label, ["tshark"], output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    available = tshark_fields()
    path = str(Path(row["path"]))
    profiles = [
        ("HTTP", "http", ["http.host", "http.request.uri", "http.file_data", "data.text", "tcp.payload"]),
        ("DNS", "dns", ["dns.qry.name", "dns.resp.name", "dns.txt", "data.data"]),
        ("ICMP", "icmp", ["icmp.type", "data.data", "data.text"]),
        ("MAIL", "smtp || imf", ["smtp.req.command", "smtp.req.parameter", "imf.subject", "imf.message_id", "data.data", "tcp.payload"]),
        ("FTP", "ftp || ftp-data", ["ftp.request.command", "ftp.request.arg", "ftp.response.arg", "data.data", "tcp.payload"]),
        ("NFS", "nfs", ["nfs.name", "nfs.file_data", "nfs.data", "data.data"]),
    ]

    sections: list[str] = []
    evidence_text = ""
    part_map: dict[int, str] = {}
    marker_re = re.compile(r"(?i)(?:part|fragment)\s*[_ -]?(\d{1,2})\s*[:=._ -]+\s*([A-Za-z0-9_@!#$%^&*()+.\-]{1,100})")

    for name, display_filter, candidates in profiles:
        fields = [x for x in candidates if x in available]
        if not fields:
            continue
        argv = [tool, "-r", path, "-Y", display_filter, "-T", "fields"]
        for field in fields:
            argv += ["-e", field]
        argv += ["-E", "separator=\t", "-E", "occurrence=a"]
        rc, output, _ = await asyncio.to_thread(wb.run_process, argv, Path(row["path"]).parent, 20)
        if rc not in {0, 1} or not output.strip():
            continue
        decoded = printable_from_hex_tokens(output)
        combined = output + ("\n" + "\n".join(decoded) if decoded else "")
        interesting = []
        for line in combined.splitlines():
            if re.search(r"(?i)flag|fragment|part\s*\d|secret|token|password|key", line):
                interesting.append(line[:2000])
            for m in marker_re.finditer(line):
                part_map.setdefault(int(m.group(1)), m.group(2).strip("_'\""))
        if interesting or decoded:
            sections.append(f"--- {name} ---\n" + "\n".join((interesting[:120] or decoded[:80])))
        evidence_text += "\n" + combined

    composed = ""
    if len(part_map) >= 2:
        numbers = sorted(part_map)
        if numbers == list(range(numbers[0], numbers[-1] + 1)):
            body = "_".join(part_map[n] for n in numbers)
            composed = f"H4G{{{body}}}"
            sections.insert(0, "Correlated numbered fragments:\n" + "\n".join(f"part{n} = {part_map[n]}" for n in numbers) + f"\n\nComposed candidate: {composed}")

    output = "\n\n".join(sections) if sections else "No obvious multi-protocol fragment markers were found. Review the protocol-specific tool outputs as well."
    scan_text = evidence_text + "\n" + composed
    found = wb.insert_flags_from_text(conn, row, scan_text, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, [tool, "-r", path, "<multi-protocol correlation>"], wb.trim_output(output), 0, "complete")
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "complete", "output": wb.trim_output(output), "flags": found}


async def nfs_recovery_analysis(conn, row, analysis_id: str, label: str):
    tool = shutil.which("tshark")
    if not tool:
        output = "tshark is not installed."
        run_id = wb.record_run(conn, row["id"], analysis_id, label, ["tshark"], output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    available = tshark_fields()
    payload_field = next((x for x in ("nfs.file_data", "nfs.data", "nfs.write.data", "nfs.read.data") if x in available), None)
    if not payload_field:
        output = "This tshark build exposes NFS decoding but no known NFS payload field (nfs.file_data/nfs.data/etc.). Use the verbose NFS analysis output."
        run_id = wb.record_run(conn, row["id"], analysis_id, label, [tool, "-G", "fields"], output, 0, "complete")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "complete", "output": output}

    handle_field = next((x for x in ("nfs.fh.hash", "nfs.filehandle") if x in available), None)
    name_field = next((x for x in ("nfs.name", "nfs.file_name") if x in available), None)
    argv = [tool, "-r", str(Path(row["path"])), "-Y", "nfs", "-T", "fields", "-e", "frame.number"]
    if handle_field:
        argv += ["-e", handle_field]
    if name_field:
        argv += ["-e", name_field]
    argv += ["-e", payload_field, "-E", "separator=\t", "-E", "occurrence=f"]
    rc, raw, status = await asyncio.to_thread(wb.run_process, argv, Path(row["path"]).parent, 35)

    groups: dict[str, bytearray] = {}
    names: dict[str, str] = {}
    for line in raw.splitlines():
        parts = line.split("\t")
        cursor = 1
        handle = "stream"
        if handle_field:
            if cursor < len(parts) and parts[cursor].strip():
                handle = parts[cursor].strip()
            cursor += 1
        filename = ""
        if name_field:
            if cursor < len(parts):
                filename = parts[cursor].strip()
            cursor += 1
        payload = parts[cursor].strip() if cursor < len(parts) else ""
        clean = re.sub(r"[^0-9A-Fa-f]", "", payload)
        if len(clean) < 2 or len(clean) % 2:
            continue
        try:
            chunk = bytes.fromhex(clean)
        except ValueError:
            continue
        groups.setdefault(handle, bytearray()).extend(chunk)
        if filename:
            names[handle] = filename

    pipeline = core.Pipeline(conn)
    children: list[str] = []
    report: list[str] = []
    scan = bytearray()
    for index, (handle, data) in enumerate(groups.items(), 1):
        if not data or len(data) > core.MAX_EXTRACTED:
            continue
        filename = core.safe_filename(names.get(handle) or f"nfs_recovered_{index:03d}.bin")
        child = pipeline.process(bytes(data), filename, parent=row["id"], origin="derived", technique=f"NFS payload reconstruction ({payload_field})", depth=1)
        children.append(child)
        report.append(f"{handle}: {filename} · {len(data):,} bytes -> {child}")
        scan.extend(data[:1024 * 1024])
        if len(children) >= 40:
            break

    output = f"Recovered {len(children)} NFS payload group(s) using {payload_field}."
    if report:
        output += "\n" + "\n".join(report)
    found = []
    for flag, confidence in core.detect_flags(bytes(scan)):
        exists = conn.execute("SELECT id FROM flags WHERE artifact_id=? AND flag=?", (row["id"], flag)).fetchone()
        if exists:
            continue
        chain = core.Pipeline(conn).technique_chain(row["id"])
        technique = f"{chain} -> NFS payload recovery" if chain else "NFS payload recovery"
        conn.execute("INSERT INTO flags(artifact_id, flag, source, technique, confidence, status) VALUES (?, ?, ?, ?, ?, 'possible')", (row["id"], flag, row["filename"], technique, confidence))
        core.add_event(conn, row["id"], "Possible flag found", flag)
        found.append(flag)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, wb.trim_output(output), rc, status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": status, "output": wb.trim_output(output), "artifacts": children, "flags": found}


def text_pattern_report(row) -> str:
    text = Path(row["path"]).read_text(encoding="utf-8", errors="replace")
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    out = [f"Non-empty lines: {len(lines)}"]
    if 3 <= len(lines) <= 500:
        out.append("First characters of lines: " + "".join(x[0] for x in lines)[:2000])
        out.append("Last characters of lines: " + "".join(x[-1] for x in lines)[:2000])
    words = re.findall(r"[A-Za-z]+", text)
    if 4 <= len(words) <= 5000:
        out.append("First letters of words (preview): " + "".join(w[0] for w in words)[:2000])
    capitals = "".join(ch for ch in text if ch.isupper())
    if capitals:
        out.append("Uppercase-only stream (preview): " + capitals[:2000])
    return "\n".join(out)


async def text_pattern_analysis(conn, row, analysis_id: str, label: str):
    try:
        output = text_pattern_report(row)
        status, rc = "complete", 0
    except Exception as exc:
        output = f"{type(exc).__name__}: {exc}"
        status, rc = "error", 1
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, ["python", "<text-patterns>"], output, rc, status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": status, "output": output, "flags": found}


def hack4gov_catalog(row):
    catalog = BASE_CATALOG(row)
    suffix = Path(row["filename"]).suffix.lower()
    kind = row["kind"]

    if repair_kinds(row):
        catalog["file.auto-repair"] = {
            "label": "Repair damaged file header",
            "tool": "python",
            "argv": ["python"],
            "auto": True,
            "special": "h4g-repair",
        }

    if suffix in {".html", ".htm", ".css", ".js", ".txt", ".svg"} or kind == "text":
        try:
            sample = Path(row["path"]).read_bytes()[:8 * 1024 * 1024]
        except OSError:
            sample = b""
        if b"data:" in sample and b";base64," in sample:
            catalog["web.embedded-data"] = {
                "label": "Extract embedded data URI objects",
                "tool": "python",
                "argv": ["python"],
                "auto": True,
                "special": "h4g-data-uri",
            }
        catalog["text.patterns"] = {
            "label": "Acrostic / text-pattern scan",
            "tool": "python",
            "argv": ["python"],
            "auto": False,
            "special": "h4g-text-patterns",
        }

    if suffix == ".csv":
        catalog["csv.coordinates"] = {
            "label": "CSV coordinate closest/farthest solver",
            "tool": "python",
            "argv": ["python"],
            "auto": True,
            "special": "h4g-csv-coordinates",
        }

    if kind in {"png", "jpeg", "gif", "bmp"} or suffix in {".png", ".jpg", ".jpeg", ".gif", ".bmp"}:
        catalog["image.qr"] = {
            "label": "QR / barcode decode",
            "tool": "zbarimg",
            "argv": ["zbarimg"],
            "auto": True,
            "special": "h4g-qr",
        }

    if kind in {"pcap", "pcapng"} or suffix in {".pcap", ".pcapng"}:
        catalog["pcap.fragment-correlation"] = {
            "label": "Multi-protocol flag-fragment correlation",
            "tool": "tshark",
            "argv": ["tshark"],
            "auto": True,
            "special": "h4g-fragments",
        }
        catalog["pcap.nfs-recovery"] = {
            "label": "NFS payload reconstruction",
            "tool": "tshark",
            "argv": ["tshark"],
            "auto": True,
            "special": "h4g-nfs-recovery",
        }

    return catalog


async def hack4gov_execute(conn, row, analysis_id: str):
    catalog = hack4gov_catalog(row)
    spec = catalog.get(analysis_id)
    if not spec:
        raise HTTPException(400, "Analysis is not available for this artifact type.")
    special = spec.get("special")
    label = spec["label"]
    if special == "h4g-repair":
        return await repair_header_analysis(conn, row, analysis_id, label)
    if special == "h4g-data-uri":
        return await embedded_data_analysis(conn, row, analysis_id, label)
    if special == "h4g-qr":
        return await qr_analysis(conn, row, analysis_id, label)
    if special == "h4g-csv-coordinates":
        return await csv_coordinate_analysis(conn, row, analysis_id, label)
    if special == "h4g-fragments":
        return await pcap_fragment_analysis(conn, row, analysis_id, label)
    if special == "h4g-nfs-recovery":
        return await nfs_recovery_analysis(conn, row, analysis_id, label)
    if special == "h4g-text-patterns":
        return await text_pattern_analysis(conn, row, analysis_id, label)
    return await BASE_EXECUTE(conn, row, analysis_id)


# Existing workbench API endpoints resolve these functions dynamically.
wb.analysis_catalog = hack4gov_catalog
wb.execute_analysis = hack4gov_execute


# ---------------------------------------------------------------------------
# Bundled challenge library
# ---------------------------------------------------------------------------


def challenge_roots() -> list[Path]:
    roots: list[Path] = []
    explicit = os.getenv("CTF_CHALLENGE_LIBRARY", "").strip()
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if p.is_dir():
            roots.append(p)

    bases = [core.ROOT, Path.cwd()]
    for base_dir in bases:
        for candidate in base_dir.glob("HACK4GOV CHALLENGES-*/HACK4GOV CHALLENGES"):
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if resolved.is_dir() and resolved not in roots:
                roots.append(resolved)
    return roots


def safe_library_path(root_index: int, relative: str) -> tuple[Path, Path]:
    roots = challenge_roots()
    if not roots:
        raise HTTPException(404, "No bundled HACK4GOV CHALLENGES directory was found. Rebuild Docker after the challenge folder is present in the repository checkout.")
    if root_index < 0 or root_index >= len(roots):
        raise HTTPException(400, "Invalid challenge-library root.")
    root = roots[root_index]
    rel = Path(relative or ".")
    if rel.is_absolute():
        raise HTTPException(400, "Library paths must be relative.")
    target = (root / rel).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise HTTPException(400, "Path escapes the challenge library.")
    if not target.exists():
        raise HTTPException(404, "Challenge-library path not found.")
    return root, target


def is_lfs_pointer(data: bytes) -> bool:
    return data.startswith(b"version https://git-lfs.github.com/spec/v1\n") and b"oid sha256:" in data[:512]


class LibraryImportRequest(BaseModel):
    root: int = 0
    path: str = Field(default="", max_length=4096)
    recursive: bool = False


class VisualCryptoRequest(BaseModel):
    artifact_a: str
    artifact_b: str


def library_items(root: Path) -> list[dict]:
    items: list[dict] = []
    for path in sorted(root.rglob("*")):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if path.is_dir():
            items.append({"path": rel, "name": path.name, "type": "dir", "size": 0})
        elif path.is_file():
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            items.append({"path": rel, "name": path.name, "type": "file", "size": size, "suffix": path.suffix.lower()})
        if len(items) >= 2000:
            break
    return items


def folder_inventory(files: list[Path], root: Path) -> dict:
    inventory = []
    hashes: dict[str, list[str]] = {}
    sizes: list[int] = []
    for path in files[:MAX_LIBRARY_FILES]:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        digest = hashlib.sha256(data).hexdigest()
        rel = path.relative_to(root).as_posix()
        entry = {"path": rel, "size": len(data), "sha256": digest}
        sizes.append(len(data))
        hashes.setdefault(digest, []).append(rel)
        if Image is not None and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".bmp"}:
            try:
                with Image.open(io.BytesIO(data)) as im:
                    entry.update({"image_width": im.width, "image_height": im.height, "image_mode": im.mode, "image_format": im.format})
            except Exception:
                pass
        inventory.append(entry)
    duplicates = [paths for paths in hashes.values() if len(paths) > 1]
    return {
        "file_count": len(inventory),
        "total_bytes": sum(x["size"] for x in inventory),
        "min_size": min(sizes) if sizes else 0,
        "max_size": max(sizes) if sizes else 0,
        "duplicates": duplicates,
        "files": inventory,
    }


async def import_library(req: LibraryImportRequest):
    root, target = safe_library_path(req.root, req.path)
    if target.is_dir() and not req.recursive:
        raise HTTPException(400, "Set recursive=true to import a challenge folder.")

    files = [target] if target.is_file() else [p for p in sorted(target.rglob("*")) if p.is_file()]
    if len(files) > MAX_LIBRARY_FILES:
        raise HTTPException(413, f"Folder contains more than {MAX_LIBRARY_FILES} files. Import a smaller subfolder.")
    total = sum(p.stat().st_size for p in files)
    if total > MAX_LIBRARY_BYTES:
        raise HTTPException(413, "Selected challenge data exceeds the configured library import limit.")

    loaded: list[tuple[Path, bytes]] = []
    lfs_missing: list[str] = []
    for path in files:
        data = path.read_bytes()
        if is_lfs_pointer(data):
            lfs_missing.append(path.relative_to(root).as_posix())
            continue
        loaded.append((path, data))

    if lfs_missing and not loaded:
        raise HTTPException(409, "The selected files are Git LFS pointer files, not the real challenge bytes. Run 'git lfs pull' locally, then rebuild Docker.")

    with core.db() as conn:
        demo_ids = wb.recursive_demo_ids(conn)
        if demo_ids:
            wb.delete_artifacts(conn, demo_ids)

        pipeline = core.Pipeline(conn)
        imported: list[str] = []
        if target.is_dir():
            inventory = folder_inventory([x[0] for x in loaded], root)
            manifest = {
                "challenge_library_root": root.name,
                "selected_path": target.relative_to(root).as_posix(),
                "inventory": inventory,
                "lfs_pointer_files_skipped": lfs_missing,
            }
            parent_id = pipeline.process(json.dumps(manifest, indent=2).encode(), "challenge_manifest.json", origin="library", technique="Hack4Gov challenge-library folder import")
            imported.append(parent_id)
            for path, data in loaded:
                rel = path.relative_to(root).as_posix()
                child = pipeline.process(data, core.safe_filename(path.name), parent=parent_id, origin="library", technique=f"Challenge library import: {rel}", depth=1)
                imported.append(child)
            root_id = parent_id
        else:
            path, data = loaded[0]
            rel = path.relative_to(root).as_posix()
            root_id = pipeline.process(data, core.safe_filename(path.name), origin="library", technique=f"Challenge library import: {rel}")
            imported.append(root_id)
        conn.commit()

    await core.hub.broadcast({"event": "challenge-library-import", "artifact_id": root_id})
    return {"ok": True, "root_artifact_id": root_id, "artifacts": imported, "files_imported": len(loaded), "lfs_pointer_files_skipped": lfs_missing}


def image_artifacts() -> list[dict]:
    with core.db() as conn:
        rows = conn.execute("SELECT id, filename, kind, size, path FROM artifacts ORDER BY created_at DESC").fetchall()
        out = []
        for row in rows:
            if row["kind"] in {"png", "jpeg", "gif", "bmp"} or Path(row["filename"]).suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".bmp"}:
                if Path(row["path"]).is_file():
                    out.append({"id": row["id"], "filename": row["filename"], "kind": row["kind"], "size": row["size"]})
        return out


async def combine_visual_crypto(req: VisualCryptoRequest):
    if Image is None or ImageChops is None:
        raise HTTPException(500, "Pillow is not installed.")
    with core.db() as conn:
        a = wb.artifact_row(conn, req.artifact_a)
        b = wb.artifact_row(conn, req.artifact_b)
        try:
            ia = Image.open(a["path"]).convert("RGB")
            ib = Image.open(b["path"]).convert("RGB")
        except Exception as exc:
            raise HTTPException(400, f"Both artifacts must be readable images: {exc}")
        if ia.size != ib.size:
            raise HTTPException(400, f"Images must have matching dimensions for visual cryptography. A={ia.size}, B={ib.size}")
        if ia.width * ia.height > 30_000_000:
            raise HTTPException(413, "Images are too large for the visual-cryptography lab.")

        outputs = {
            "difference": ImageChops.difference(ia, ib),
            "multiply": ImageChops.multiply(ia, ib),
            "screen": ImageChops.screen(ia, ib),
            "lighter": ImageChops.lighter(ia, ib),
            "darker": ImageChops.darker(ia, ib),
            "blend50": Image.blend(ia, ib, 0.5),
        }
        la, lb = ia.convert("L"), ib.convert("L")
        xor_bytes = bytes(x ^ y for x, y in zip(la.tobytes(), lb.tobytes()))
        outputs["xor"] = Image.frombytes("L", la.size, xor_bytes).convert("RGB")

        pipeline = core.Pipeline(conn)
        children = []
        for mode, image in outputs.items():
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            child = pipeline.process(buffer.getvalue(), f"visual_crypto_{mode}.png", parent=a["id"], origin="derived", technique=f"Visual cryptography {mode} with {b['id']}", depth=1)
            children.append({"mode": mode, "artifact_id": child})
        conn.commit()

    await core.hub.broadcast({"event": "visual-crypto", "artifact_id": req.artifact_a})
    return {"ok": True, "results": children}


# ---------------------------------------------------------------------------
# Outer Hack4Gov application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="H4G CTF Workbench - Hack4Gov Pack",
    version="0.4.0",
    description="Challenge-pack-aware local/authorized CTF analysis workbench.",
)


@app.get("/")
def h4g_home():
    return FileResponse(core.ROOT / "frontend" / "hack4gov_home.html")


@app.get("/challenge-library")
def challenge_library_page():
    return FileResponse(core.ROOT / "frontend" / "challenge_library.html")


@app.get("/visual-crypto")
def visual_crypto_page():
    return FileResponse(core.ROOT / "frontend" / "visual_crypto.html")


@app.get("/api/h4g/coverage")
def h4g_coverage():
    roots = challenge_roots()
    return {
        "version": "0.4.0",
        "challenge_library_roots": [str(x) for x in roots],
        "features": [
            "bundled Hack4Gov challenge library",
            "damaged PNG/JPEG/WAV header repair and prepended-file carving",
            "QR/barcode decoding",
            "embedded HTML/CSS data-URI extraction",
            "CSV-aware coordinate closest/farthest solver",
            "multi-protocol PCAP flag-fragment correlation",
            "NFS payload reconstruction",
            "visual cryptography image combinations",
            "acrostic/text pattern helper",
        ],
    }


@app.get("/api/h4g/library")
def get_library():
    roots = challenge_roots()
    return {
        "roots": [
            {
                "index": index,
                "name": root.name,
                "path": str(root),
                "items": library_items(root),
            }
            for index, root in enumerate(roots)
        ]
    }


@app.get("/api/h4g/library/inventory")
def get_library_inventory(root: int = 0, path: str = ""):
    base_root, target = safe_library_path(root, path)
    files = [target] if target.is_file() else [p for p in sorted(target.rglob("*")) if p.is_file()]
    if len(files) > MAX_LIBRARY_FILES:
        files = files[:MAX_LIBRARY_FILES]
    return folder_inventory(files, base_root)


@app.post("/api/h4g/library/import")
async def post_library_import(req: LibraryImportRequest):
    return await import_library(req)


@app.get("/api/h4g/visual-crypto/images")
def visual_crypto_images():
    return image_artifacts()


@app.post("/api/h4g/visual-crypto/combine")
async def visual_crypto_combine(req: VisualCryptoRequest):
    return await combine_visual_crypto(req)


# challenge_pack retains /workbench, /web-lab, robust uploads, and all legacy APIs.
app.mount("/", base.app)
