from __future__ import annotations

import asyncio
import email
import ipaddress
import math
import re
import shutil
import socket
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend import main as core
from backend import recovery as recovery
from backend import workbench as wb


# Keep the original workbench behavior and extend it rather than replacing it.
BASE_CATALOG = wb.analysis_catalog
BASE_EXECUTE = wb.execute_analysis


# ============================================================
# Challenge-family helpers
# ============================================================

COMMON_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF87a"),
    (b"GIF89a", "GIF89a"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/Windows executable"),
    (b"RIFF", "RIFF/WAV or AVI"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"7z\xbc\xaf'\x1c", "7-Zip"),
    (b"Rar!\x1a\x07", "RAR"),
]


def safe_read(row, limit: int = 2 * 1024 * 1024) -> bytes:
    path = Path(row["path"])
    with path.open("rb") as f:
        return f.read(limit)


def signature_scan(row) -> str:
    data = safe_read(row, 4 * 1024 * 1024)
    hits = []
    for sig, name in COMMON_SIGNATURES:
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos < 0:
                break
            hits.append((pos, name, sig.hex(" ").upper()))
            start = pos + 1
            if len(hits) >= 100:
                break
        if len(hits) >= 100:
            break

    if not hits:
        return "No common embedded signatures found in the first 4 MiB."

    lines = ["Common file signatures found:"]
    for offset, name, magic in sorted(hits):
        location = "file start" if offset == 0 else f"offset 0x{offset:X}"
        lines.append(f"- {name}: {location} ({magic})")

    if hits and hits[0][0] > 0:
        lines.append("\nThe first recognizable signature is not at byte 0. This can indicate a damaged header, prepended data, or a carved/embedded file.")

    return "\n".join(lines)


def whitespace_analysis(row) -> str:
    data = safe_read(row)
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()

    trailing = []
    tabs = 0
    spaces = 0
    stream = []

    for number, line in enumerate(lines, 1):
        m = re.search(r"([ \t]+)$", line)
        if not m:
            continue
        suffix = m.group(1)
        trailing.append((number, suffix))
        tabs += suffix.count("\t")
        spaces += suffix.count(" ")
        stream.extend("1" if ch == "\t" else "0" for ch in suffix)

    out = [
        f"Lines with trailing spaces/tabs: {len(trailing)}",
        f"Trailing spaces: {spaces}",
        f"Trailing tabs: {tabs}",
    ]

    if trailing:
        out.append("\nFirst trailing-whitespace lines:")
        for number, suffix in trailing[:80]:
            visible = suffix.replace(" ", "·").replace("\t", "→")
            out.append(f"{number}: {visible}")

    if len(stream) >= 8:
        decoded = bytearray()
        for i in range(0, len(stream) - 7, 8):
            decoded.append(int("".join(stream[i:i + 8]), 2))
        printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in decoded)
        out.append("\nSpace=0 / tab=1 byte interpretation:")
        out.append(printable[:4096])

    return "\n".join(out)


def coordinate_analysis(row) -> str:
    data = safe_read(row)
    text = data.decode("utf-8", errors="ignore")
    pattern = re.compile(r"(?<![\d.])(-?\d{1,3}(?:\.\d+))\s*[,; ]\s*(-?\d{1,3}(?:\.\d+))(?![\d.])")
    coords = []
    for idx, m in enumerate(pattern.finditer(text), 1):
        lat = float(m.group(1))
        lon = float(m.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            prefix = text[max(0, m.start() - 40):m.start()]
            id_match = re.search(r"([A-Za-z0-9_-]{1,30})\s*[:=,-]?\s*$", prefix)
            label = id_match.group(1) if id_match else f"coord{idx}"
            coords.append((label, lat, lon))

    if not coords:
        return "No decimal GPS coordinate pairs detected."

    def haversine(a, b):
        _, lat1, lon1 = a
        _, lat2, lon2 = b
        r = 6371.0088
        p1, p2 = math.radians(lat1), math.radians(lat2)
        dp = math.radians(lat2 - lat1)
        dl = math.radians(lon2 - lon1)
        h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
        return 2 * r * math.asin(math.sqrt(h))

    pairs = []
    for i in range(len(coords)):
        for j in range(i + 1, len(coords)):
            pairs.append((haversine(coords[i], coords[j]), coords[i], coords[j]))

    out = [f"Detected coordinates: {len(coords)}"]
    for label, lat, lon in coords[:100]:
        out.append(f"- {label}: {lat}, {lon}")

    if pairs:
        closest = min(pairs, key=lambda x: x[0])
        farthest = max(pairs, key=lambda x: x[0])
        out.extend([
            "",
            f"Closest: {closest[1][0]} ↔ {closest[2][0]} = {closest[0]:.3f} km",
            f"Farthest: {farthest[1][0]} ↔ {farthest[2][0]} = {farthest[0]:.3f} km",
        ])

    return "\n".join(out)


def email_analysis(row) -> str:
    data = Path(row["path"]).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(data)

    fields = ["From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID", "Return-Path"]
    out = ["Email headers:"]
    for name in fields:
        value = msg.get(name)
        if value:
            out.append(f"{name}: {value}")

    received = msg.get_all("Received", [])
    if received:
        out.append("\nReceived chain:")
        out.extend(f"- {x}" for x in received[:20])

    attachments = []
    bodies = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments.append(f"{filename} ({part.get_content_type()})")
        if part.get_content_type() in {"text/plain", "text/html"}:
            try:
                bodies.append(part.get_content())
            except Exception:
                pass

    if attachments:
        out.append("\nAttachments:")
        out.extend(f"- {x}" for x in attachments)

    if bodies:
        out.append("\nBody preview:")
        out.append("\n".join(str(x) for x in bodies)[:12000])

    return "\n".join(out)


HID_NORMAL = {
    0x04:"a",0x05:"b",0x06:"c",0x07:"d",0x08:"e",0x09:"f",0x0A:"g",0x0B:"h",0x0C:"i",0x0D:"j",0x0E:"k",0x0F:"l",
    0x10:"m",0x11:"n",0x12:"o",0x13:"p",0x14:"q",0x15:"r",0x16:"s",0x17:"t",0x18:"u",0x19:"v",0x1A:"w",0x1B:"x",0x1C:"y",0x1D:"z",
    0x1E:"1",0x1F:"2",0x20:"3",0x21:"4",0x22:"5",0x23:"6",0x24:"7",0x25:"8",0x26:"9",0x27:"0",
    0x28:"\n",0x2A:"<BACKSPACE>",0x2B:"\t",0x2C:" ",0x2D:"-",0x2E:"=",0x2F:"[",0x30:"]",0x31:"\\",0x33:";",0x34:"'",0x35:"`",0x36:",",0x37:".",0x38:"/",
}
HID_SHIFT = {
    0x1E:"!",0x1F:"@",0x20:"#",0x21:"$",0x22:"%",0x23:"^",0x24:"&",0x25:"*",0x26:"(",0x27:")",
    0x2D:"_",0x2E:"+",0x2F:"{",0x30:"}",0x31:"|",0x33:":",0x34:'"',0x35:"~",0x36:"<",0x37:">",0x38:"?",
}


def decode_hid_reports(reports: list[bytes], xor_key: int | None = None) -> str:
    out = []
    previous = set()
    for raw in reports:
        b = bytes((x ^ xor_key) if xor_key is not None else x for x in raw)
        if len(b) < 8:
            previous = set()
            continue
        modifier = b[0]
        shift = bool(modifier & 0x22)
        keys = {x for x in b[2:8] if x}
        new_keys = [x for x in b[2:8] if x and x not in previous]
        for code in new_keys:
            value = HID_SHIFT.get(code) if shift else None
            if value is None:
                value = HID_NORMAL.get(code, "")
                if shift and len(value) == 1 and value.isalpha():
                    value = value.upper()
            out.append(value)
        previous = keys
    return "".join(out)


async def usb_hid_analysis(conn, row, analysis_id: str, label: str):
    tshark = shutil.which("tshark")
    path = str(Path(row["path"]))
    attempts = [
        [tshark or "tshark", "-r", path, "-Y", "usb.capdata", "-T", "fields", "-e", "usb.capdata"],
        [tshark or "tshark", "-r", path, "-Y", "usbhid.data", "-T", "fields", "-e", "usbhid.data"],
    ]
    if not tshark:
        output = "tshark is not installed."
        run_id = wb.record_run(conn, row["id"], analysis_id, label, attempts[0], output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    reports = []
    used = attempts[0]
    rc, raw_text, status = await asyncio.to_thread(wb.run_process, attempts[0])
    if not raw_text.strip() or rc != 0:
        used = attempts[1]
        rc, raw_text, status = await asyncio.to_thread(wb.run_process, attempts[1])

    for line in raw_text.splitlines():
        clean = re.sub(r"[^0-9A-Fa-f]", "", line)
        if len(clean) >= 16 and len(clean) % 2 == 0:
            try:
                reports.append(bytes.fromhex(clean))
            except ValueError:
                pass

    direct = decode_hid_reports(reports)
    scored = []
    for key in range(256):
        text = decode_hid_reports(reports, key)
        if not text:
            continue
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in text) / max(1, len(text))
        bonus = 0.0
        upper = text.upper()
        if "H4G{" in upper or "FLAG{" in upper or "CTF{" in upper:
            bonus += 2.0
        if re.search(r"[A-Za-z]{4,}", text):
            bonus += 0.25
        scored.append((printable + bonus, key, text))

    out = [f"HID reports recovered: {len(reports)}", "", "Direct HID decode:", direct[:12000] or "(none)"]
    if scored:
        out.append("\nTop single-byte XOR + HID candidates:")
        for score, key, text in sorted(scored, reverse=True)[:8]:
            out.append(f"\n[key 0x{key:02X}, score {score:.3f}]\n{text[:5000]}")

    output = wb.trim_output("\n".join(out))
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, used, output, rc, status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": status, "output": output, "flags": found}


async def spectrogram_analysis(conn, row, analysis_id: str, label: str):
    sox = shutil.which("sox")
    argv = [sox or "sox", str(Path(row["path"])), "-n", "spectrogram"]
    if not sox:
        output = "sox is not installed."
        run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    out_path = Path(row["path"]).parent / "spectrogram.png"
    out_path.unlink(missing_ok=True)
    argv = [sox, str(Path(row["path"])), "-n", "spectrogram", "-o", str(out_path)]
    rc, process_output, status = await asyncio.to_thread(wb.run_process, argv, Path(row["path"]).parent, 45)
    children = []
    if out_path.is_file() and out_path.stat().st_size > 0:
        pipeline = core.Pipeline(conn)
        child = pipeline.process(out_path.read_bytes(), "spectrogram.png", parent=row["id"], origin="derived", technique="SoX spectrogram", depth=1)
        children.append(child)
    output = (process_output or "Spectrogram generated.") + (f"\nImported artifact: {children[0]}" if children else "")
    run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, wb.trim_output(output), rc, status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": status, "output": wb.trim_output(output), "artifacts": children}


async def pdf_images_analysis(conn, row, analysis_id: str, label: str):
    tool = shutil.which("pdfimages")
    if not tool:
        output = "pdfimages is not installed."
        argv = ["pdfimages"]
        run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    outdir = Path(row["path"]).parent / "pdf_images"
    shutil.rmtree(outdir, ignore_errors=True)
    outdir.mkdir(parents=True, exist_ok=True)
    prefix = outdir / "image"
    argv = [tool, "-png", str(Path(row["path"])), str(prefix)]
    rc, process_output, status = await asyncio.to_thread(wb.run_process, argv, outdir, 45)
    pipeline = core.Pipeline(conn)
    children = []
    for candidate in sorted(outdir.glob("*.png"))[:40]:
        if candidate.stat().st_size <= 0 or candidate.stat().st_size > core.MAX_EXTRACTED:
            continue
        children.append(pipeline.process(candidate.read_bytes(), candidate.name, parent=row["id"], origin="derived", technique="PDF image extraction", depth=1))
    output = (process_output or "") + f"\nExtracted/imported {len(children)} PDF image(s)."
    run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, wb.trim_output(output), rc, status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": status, "output": wb.trim_output(output), "artifacts": children}


async def internal_analysis(conn, row, analysis_id: str, label: str, fn):
    try:
        output = fn(row)
        status = "complete"
        rc = 0
    except Exception as exc:
        output = f"{type(exc).__name__}: {exc}"
        status = "error"
        rc = 1
    found = wb.insert_flags_from_text(conn, row, output, label)
    argv = ["python", f"<{analysis_id}>"]
    run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, wb.trim_output(output), rc, status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": status, "output": wb.trim_output(output), "flags": found}


# ============================================================
# Extended analysis catalog
# ============================================================


def challenge_catalog(row):
    catalog = BASE_CATALOG(row)
    path = str(Path(row["path"]))
    kind = row["kind"]
    suffix = Path(row["filename"]).suffix.lower()

    catalog["file.signature-scan"] = {
        "label": "Signature / damaged-header scan",
        "tool": "python",
        "argv": ["python"],
        "auto": True,
        "special": "signature-scan",
    }

    data_sample = b""
    if kind == "text" or suffix in {".txt", ".csv", ".log", ".eml"}:
        try:
            data_sample = safe_read(row)
        except Exception:
            pass

    if kind == "text" or suffix in {".txt", ".csv", ".log"}:
        text = data_sample.decode("utf-8", errors="ignore")
        if re.search(r"[ \t]+$", text, re.M):
            catalog["text.whitespace"] = {
                "label": "Whitespace steganography scan",
                "tool": "python",
                "argv": ["python"],
                "auto": True,
                "special": "whitespace",
            }
        if re.search(r"-?\d{1,3}\.\d+\s*[,; ]\s*-?\d{1,3}\.\d+", text):
            catalog["text.coordinates"] = {
                "label": "GPS coordinate distance analysis",
                "tool": "python",
                "argv": ["python"],
                "auto": True,
                "special": "coordinates",
            }

    emailish = suffix == ".eml" or b"Message-ID:" in data_sample or (b"From:" in data_sample and b"Subject:" in data_sample)
    if emailish:
        catalog["mail.headers"] = {
            "label": "Email headers / Message-ID / attachments",
            "tool": "python",
            "argv": ["python"],
            "auto": True,
            "special": "email",
        }

    if kind == "wav" or suffix in {".wav", ".flac", ".mp3", ".ogg"}:
        catalog["audio.ffprobe"] = {
            "label": "Audio stream metadata",
            "tool": "ffprobe",
            "argv": ["ffprobe", "-hide_banner", "-show_format", "-show_streams", path],
            "auto": True,
        }
        catalog["audio.sox-stats"] = {
            "label": "Audio signal statistics",
            "tool": "sox",
            "argv": ["sox", path, "-n", "stat"],
            "auto": True,
        }
        catalog["audio.spectrogram"] = {
            "label": "Generate spectrogram",
            "tool": "sox",
            "argv": ["sox"],
            "auto": True,
            "special": "spectrogram",
        }

    if kind == "pdf" or suffix == ".pdf":
        catalog["pdf.info"] = {
            "label": "PDF metadata / structure summary",
            "tool": "pdfinfo",
            "argv": ["pdfinfo", path],
            "auto": True,
        }
        catalog["pdf.text"] = {
            "label": "Extract PDF text",
            "tool": "pdftotext",
            "argv": ["pdftotext", "-layout", path, "-"],
            "auto": True,
        }
        catalog["pdf.images"] = {
            "label": "Extract embedded PDF images",
            "tool": "pdfimages",
            "argv": ["pdfimages"],
            "auto": True,
            "special": "pdf-images",
        }

    if kind in {"zip", "gzip", "bzip2", "rar", "7z"} or suffix in {".zip", ".gz", ".bz2", ".rar", ".7z", ".tar", ".tgz"}:
        catalog["archive.libarchive-list"] = {
            "label": "Multi-format archive listing",
            "tool": "bsdtar",
            "argv": ["bsdtar", "-tvf", path],
            "auto": True,
        }

    if kind in {"pcap", "pcapng"}:
        catalog.update({
            "pcap.icmp": {
                "label": "ICMP / ping payloads",
                "tool": "tshark",
                "argv": ["tshark", "-r", path, "-Y", "icmp", "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "icmp.type", "-e", "data.data"],
                "auto": True,
            },
            "pcap.ftp": {
                "label": "FTP commands and data",
                "tool": "tshark",
                "argv": ["tshark", "-r", path, "-Y", "ftp || ftp-data", "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "ftp.request.command", "-e", "ftp.request.arg", "-e", "ftp.response.arg", "-e", "tcp.payload"],
                "auto": True,
            },
            "pcap.mail": {
                "label": "SMTP / email traffic",
                "tool": "tshark",
                "argv": ["tshark", "-r", path, "-Y", "smtp || imf", "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "smtp.req.command", "-e", "smtp.req.parameter", "-e", "imf.subject", "-e", "imf.message_id", "-e", "tcp.payload"],
                "auto": True,
            },
            "pcap.nfs": {
                "label": "NFS traffic and leaked filenames",
                "tool": "tshark",
                "argv": ["tshark", "-r", path, "-Y", "nfs", "-V"],
                "auto": True,
            },
            "pcap.usb-hid": {
                "label": "USB HID / keylogger + XOR decoder",
                "tool": "tshark",
                "argv": ["tshark"],
                "auto": True,
                "special": "usb-hid",
            },
        })

    return catalog


async def challenge_execute(conn, row, analysis_id: str):
    catalog = challenge_catalog(row)
    spec = catalog.get(analysis_id)
    if not spec:
        raise HTTPException(400, "Analysis is not available for this artifact type.")

    special = spec.get("special")
    label = spec["label"]
    if special == "signature-scan":
        return await internal_analysis(conn, row, analysis_id, label, signature_scan)
    if special == "whitespace":
        return await internal_analysis(conn, row, analysis_id, label, whitespace_analysis)
    if special == "coordinates":
        return await internal_analysis(conn, row, analysis_id, label, coordinate_analysis)
    if special == "email":
        return await internal_analysis(conn, row, analysis_id, label, email_analysis)
    if special == "usb-hid":
        return await usb_hid_analysis(conn, row, analysis_id, label)
    if special == "spectrogram":
        return await spectrogram_analysis(conn, row, analysis_id, label)
    if special == "pdf-images":
        return await pdf_images_analysis(conn, row, analysis_id, label)
    return await BASE_EXECUTE(conn, row, analysis_id)


# Patch the workbench module. Its existing API endpoints resolve these globals at
# request time, so all current UI buttons automatically gain the new analyzers.
wb.analysis_catalog = challenge_catalog
wb.execute_analysis = challenge_execute


# ============================================================
# Authorized web challenge lab
# ============================================================


def ensure_scope_db():
    with core.db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS authorized_web_targets(
                host TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


ensure_scope_db()


class ScopeRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)


class WebRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    method: str = "GET"
    body: str = Field(default="", max_length=65536)
    follow_redirects: bool = False


def configured_hosts() -> set[str]:
    return {str(x).lower().strip(".") for x in core.CONFIG.get("web", {}).get("authorized_targets", [])}


def literal_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def resolves_only_private(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    ips = {info[4][0] for info in infos}
    if not ips:
        return False
    try:
        return all(ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback for ip in ips)
    except ValueError:
        return False


def is_authorized_host(host: str) -> bool:
    host = host.lower().strip(".")
    if host in configured_hosts() or literal_private(host) or resolves_only_private(host):
        return True
    with core.db() as conn:
        row = conn.execute("SELECT host FROM authorized_web_targets WHERE host=?", (host,)).fetchone()
        return bool(row)


def validate_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "Only http:// and https:// targets are supported.")
    if not is_authorized_host(parsed.hostname):
        raise HTTPException(403, f"Target '{parsed.hostname}' is not in authorized scope. Add it in Web Lab first.")
    return parsed


async def fetch_authorized(req: WebRequest):
    method = req.method.upper()
    if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
        raise HTTPException(400, "Allowed methods: GET, HEAD, POST, OPTIONS.")

    current = req.url
    history = []
    max_redirects = int(core.CONFIG.get("web", {}).get("max_redirects", 10))
    timeout = float(core.CONFIG.get("web", {}).get("request_timeout_seconds", 10))

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
        for _ in range(max_redirects + 1):
            validate_url(current)
            started = time.perf_counter()
            response = await client.request(method, current, content=req.body.encode() if req.body else None)
            elapsed_ms = (time.perf_counter() - started) * 1000
            body_bytes = response.content[:1024 * 1024]
            body_text = body_bytes.decode("utf-8", errors="replace")
            history.append({
                "url": str(response.url),
                "status": response.status_code,
                "elapsed_ms": round(elapsed_ms, 3),
                "headers": dict(response.headers),
                "body": body_text,
                "flags": [flag for flag, _ in core.detect_flags(body_bytes)],
            })

            if not req.follow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
                break
            location = response.headers.get("location")
            if not location:
                break
            current = urljoin(str(response.url), location)
            if response.status_code == 303:
                method = "GET"

    return history


# ============================================================
# Outer app / portal
# ============================================================

app = FastAPI(
    title="H4G CTF Challenge Pack Workbench",
    version="0.3.0",
    description="Expanded local/authorized workbench aligned to Hack4Gov-style challenge families.",
)


@app.get("/")
def portal():
    return FileResponse(core.ROOT / "frontend" / "challenge_home.html")


@app.get("/workbench")
def artifact_workbench():
    return FileResponse(core.ROOT / "frontend" / "workbench.html")


@app.get("/web-lab")
def web_lab():
    return FileResponse(core.ROOT / "frontend" / "web_lab.html")


@app.get("/api/challenge-pack/coverage")
def coverage():
    return {
        "version": "0.3.0",
        "families": [
            "file forensics and damaged headers",
            "archives and recursive extraction",
            "image steganography and metadata",
            "audio metadata, statistics, and spectrograms",
            "PDF text and embedded images",
            "email headers, Message-ID, bodies, and attachments",
            "PCAP HTTP/DNS/ICMP/FTP/SMTP/NFS/TCP/object extraction",
            "USB HID/keylogger decoding with single-byte XOR candidates",
            "whitespace steganography",
            "GPS coordinate distance analysis",
            "static executable analysis",
            "authorized web request/redirect inspection",
        ],
    }


@app.get("/api/tools")
def expanded_tools():
    names = [
        "file", "strings", "xxd", "exiftool", "binwalk", "foremost", "tshark",
        "radare2", "rabin2", "readelf", "objdump", "nm", "zsteg", "steghide", "upx",
        "ffmpeg", "ffprobe", "sox", "pdfinfo", "pdftotext", "pdfimages", "bsdtar",
    ]
    return [{"name": name, "available": shutil.which(name) is not None, "path": shutil.which(name)} for name in names]


@app.get("/api/web/scope")
def get_scope():
    with core.db() as conn:
        rows = conn.execute("SELECT host, created_at FROM authorized_web_targets ORDER BY host").fetchall()
    return {
        "configured": sorted(configured_hosts()),
        "dynamic": [dict(x) for x in rows],
        "private_ranges_allowed": True,
    }


@app.post("/api/web/scope")
def add_scope(req: ScopeRequest):
    host = req.host.lower().strip().strip(".")
    if "/" in host or "://" in host or not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
        raise HTTPException(400, "Enter a hostname or IP address only.")
    with core.db() as conn:
        conn.execute("INSERT OR REPLACE INTO authorized_web_targets(host, created_at) VALUES (?, ?)", (host, core.now()))
        conn.commit()
    return {"ok": True, "host": host}


@app.post("/api/web/fetch")
async def web_fetch(req: WebRequest):
    history = await fetch_authorized(req)
    return {"history": history}


# Recovery app contains robust upload handling and mounts the original workbench.
app.mount("/", recovery.app)
