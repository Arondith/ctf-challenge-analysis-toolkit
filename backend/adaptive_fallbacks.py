from __future__ import annotations

import base64
import binascii
import codecs
import io
import math
import re
import shutil
import struct
import tempfile
import urllib.parse
from pathlib import Path

from fastapi import HTTPException
from PIL import Image, ImageEnhance, ImageOps

from backend import main as core
from backend import workbench as wb

# Imported after fallback_analyzers. Extend the complete safe registry rather than
# bypassing it.
BASE_CATALOG = wb.analysis_catalog
BASE_EXECUTE = wb.execute_analysis

MAX_BRANCHES = 12
MAX_SOURCE_STRINGS = 180
PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"

# Machine-readable capability redundancy. A failed/empty primary automatically
# promotes genuinely different implementations on the same artifact.
FALLBACK_RULES = {
    "file.binwalk": ["fallback.raw-signature-scan"],
    "deep.foremost": ["fallback.raw-signature-scan"],
    "archive.list": ["fallback.python-archive", "fallback.raw-signature-scan"],
    "image.zsteg": ["fallback.image-lsb", "fallback.image-ocr"],
    "stego.steghide": ["fallback.image-lsb", "fallback.image-ocr", "fallback.raw-signature-scan"],
    "pcap.protocols": ["fallback.pcap-dpkt", "fallback.pcap-scapy"],
    "pcap.data": ["fallback.pcap-dpkt", "fallback.pcap-scapy"],
    "pcap.stream-scan": ["fallback.pcap-dpkt", "fallback.pcap-scapy", "fallback.raw-signature-scan"],
    "pcap.export-objects": ["fallback.pcap-dpkt", "fallback.pcap-scapy", "fallback.raw-signature-scan"],
    "binary.rabin2": ["fallback.pefile", "fallback.raw-signature-scan"],
    "binary.radare2": ["fallback.pefile", "fallback.raw-signature-scan"],
    "binary.pyinstaller-extract": ["fallback.pyinstaller-raw", "fallback.pefile", "fallback.raw-signature-scan"],
    "pdf.text": ["fallback.pypdf"],
    "pdf.info": ["fallback.pypdf"],
}

LOW_INFORMATION_PATTERNS = (
    "no embedded data",
    "nothing found",
    "no known embedded signatures",
    "extracted 0 network object",
    "imported 0 carved object",
    "0 barcode",
    "no barcode",
    "no qr",
    "no useful",
)


def _finish(conn, row, analysis_id: str, label: str, output: str, *, status="complete", rc=0, artifacts=None):
    text = wb.trim_output(output)
    flags = wb.insert_flags_from_text(conn, row, text, label)
    run_id = wb.record_run(
        conn, row["id"], analysis_id, label,
        ["python", f"<{analysis_id}>"], text, rc, status,
    )
    result = {
        "id": run_id,
        "analysis_id": analysis_id,
        "label": label,
        "status": status,
        "returncode": rc,
        "output": text,
        "flags": flags,
    }
    if artifacts is not None:
        result["artifacts"] = artifacts
    return result


def _latest_runs(artifact_id: str) -> dict[str, dict]:
    try:
        with core.db() as conn:
            rows = conn.execute(
                """
                SELECT analysis_id,status,returncode,output
                FROM tool_runs WHERE artifact_id=? ORDER BY id DESC LIMIT 120
                """,
                (artifact_id,),
            ).fetchall()
    except Exception:
        return {}
    out = {}
    for row in rows:
        out.setdefault(row["analysis_id"], dict(row))
    return out


def _run_needs_fallback(run: dict | None) -> bool:
    if not run:
        return False
    status = str(run.get("status") or "").lower()
    rc = run.get("returncode")
    text = str(run.get("output") or "").lower()
    if status in {"missing", "timeout", "error"}:
        return True
    if isinstance(rc, int) and rc not in {0, 1}:
        return True
    if not text.strip():
        return True
    return any(pattern in text for pattern in LOW_INFORMATION_PATTERNS)


def _printable_score(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:65536]
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(sample)


def _looks_interesting(data: bytes) -> tuple[bool, str]:
    if not data:
        return False, "empty"
    flags = core.detect_flags(data)
    if flags:
        return True, "flag-shaped evidence"
    signatures = (
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"PK\x03\x04", "ZIP"),
        (b"%PDF-", "PDF"),
        (b"MZ", "PE"),
        (b"RIFF", "RIFF"),
        (b"\x1f\x8b", "gzip"),
    )
    for sig, name in signatures:
        if data.startswith(sig):
            return True, f"{name} signature"
    score = _printable_score(data)
    if score >= 0.82 and len(data) >= 6:
        return True, f"printability={score:.2f}"
    return False, f"printability={score:.2f}"


def _safe_b64(value: bytes) -> bytes | None:
    compact = re.sub(rb"\s+", b"", value)
    if len(compact) < 8 or not re.fullmatch(rb"[A-Za-z0-9+/=_-]+", compact):
        return None
    try:
        pad = b"=" * ((4 - len(compact) % 4) % 4)
        return base64.urlsafe_b64decode(compact + pad)
    except Exception:
        return None


def _safe_b32(value: bytes) -> bytes | None:
    compact = re.sub(rb"\s+", b"", value.upper())
    if len(compact) < 8 or not re.fullmatch(rb"[A-Z2-7=]+", compact):
        return None
    try:
        pad = b"=" * ((8 - len(compact) % 8) % 8)
        return base64.b32decode(compact + pad, casefold=True)
    except Exception:
        return None


def _safe_hex(value: bytes) -> bytes | None:
    compact = re.sub(rb"(?:0x)|[^0-9A-Fa-f]", b"", value)
    if len(compact) < 8 or len(compact) % 2:
        return None
    try:
        return bytes.fromhex(compact.decode("ascii"))
    except Exception:
        return None


async def decode_branch_search(conn, row, analysis_id: str, label: str):
    try:
        raw = Path(row["path"]).read_bytes()
        source_strings = core.strings(raw[:4 * 1024 * 1024], 6)[:MAX_SOURCE_STRINGS]
        candidates: list[tuple[str, bytes]] = []
        seen = set()

        # Whole-file text is useful for text-like challenges; strings handle binary carriers.
        if core.printable_ratio(raw[:65536]) >= 0.60:
            source_strings.insert(0, raw[:65536].decode("utf-8", errors="ignore"))

        for index, text in enumerate(source_strings):
            blob = text.encode("utf-8", errors="ignore")[:8192]
            transforms = {
                "base64": _safe_b64(blob),
                "base32": _safe_b32(blob),
                "hex": _safe_hex(blob),
            }
            try:
                decoded_url = urllib.parse.unquote_to_bytes(text)
                if decoded_url != blob:
                    transforms["url"] = decoded_url
            except Exception:
                pass
            try:
                rot = codecs.decode(text, "rot_13").encode("utf-8", errors="ignore")
                if rot != blob:
                    transforms["rot13"] = rot
            except Exception:
                pass

            # Bounded single-byte XOR. Keep only outputs that become strongly printable
            # or reveal a known signature/flag.
            for key in range(256):
                decoded = bytes(b ^ key for b in blob)
                interesting, why = _looks_interesting(decoded)
                if interesting and ("flag" in why or "signature" in why or _printable_score(decoded) >= 0.92):
                    transforms[f"xor-{key:02x}"] = decoded
                    if sum(1 for k in transforms if k.startswith("xor-")) >= 2:
                        break

            for method, decoded in transforms.items():
                if not decoded or decoded == blob:
                    continue
                interesting, why = _looks_interesting(decoded)
                digest = binascii.crc32(decoded) & 0xFFFFFFFF
                token = (method, digest, len(decoded))
                if interesting and token not in seen:
                    seen.add(token)
                    candidates.append((f"string#{index}:{method}:{why}", decoded))
                    if len(candidates) >= MAX_BRANCHES:
                        break
            if len(candidates) >= MAX_BRANCHES:
                break

        pipeline = core.Pipeline(conn)
        children = []
        notes = [f"Promising decode branches: {len(candidates)}"]
        for idx, (why, decoded) in enumerate(candidates):
            child = pipeline.process(
                decoded,
                f"decoded_branch_{idx:02d}.bin",
                parent=row["id"],
                origin="derived",
                technique=f"Autopilot bounded decode branch: {why}",
                depth=1,
            )
            children.append(child)
            notes.append(f"- {child}: {why}; {len(decoded)} bytes")
        if not candidates:
            notes.append("No decode branch crossed the relevance threshold; alternate families remain available.")
        return _finish(conn, row, analysis_id, label, "\n".join(notes), artifacts=children)
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", status="error", rc=1, artifacts=[])


async def scapy_pcap(conn, row, analysis_id: str, label: str):
    try:
        from scapy.all import DNS, ICMP, IP, IPv6, Raw, TCP, UDP, PcapReader

        counts = {}
        payload_text = []
        endpoints = {}
        packets = 0
        with PcapReader(str(Path(row["path"]))) as reader:
            for packet in reader:
                packets += 1
                if packets > 200000:
                    break
                for name, layer in (("TCP", TCP), ("UDP", UDP), ("DNS", DNS), ("ICMP", ICMP)):
                    if packet.haslayer(layer):
                        counts[name] = counts.get(name, 0) + 1
                src = dst = None
                if packet.haslayer(IP):
                    src, dst = packet[IP].src, packet[IP].dst
                elif packet.haslayer(IPv6):
                    src, dst = packet[IPv6].src, packet[IPv6].dst
                if src and dst:
                    endpoints[(src, dst)] = endpoints.get((src, dst), 0) + 1
                if packet.haslayer(Raw) and len(payload_text) < 240:
                    data = bytes(packet[Raw].load)
                    text = "\n".join(core.strings(data, 4)[:8])
                    if text:
                        payload_text.append(text)

        notes = [f"Packets parsed with Scapy: {packets}"]
        notes.append("Protocols: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        notes.append("Top endpoint pairs:")
        for (src, dst), count in sorted(endpoints.items(), key=lambda x: x[1], reverse=True)[:30]:
            notes.append(f"- {src} -> {dst}: {count}")
        if payload_text:
            notes.append("\nPrintable payload evidence:\n" + "\n---\n".join(payload_text[:100]))
        return _finish(conn, row, analysis_id, label, "\n".join(notes))
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", status="error", rc=1)


def _ocr_variants(image: Image.Image):
    gray = ImageOps.grayscale(image)
    yield "grayscale", gray
    yield "invert", ImageOps.invert(gray)
    enhanced = ImageEnhance.Contrast(gray).enhance(2.2)
    yield "contrast", enhanced
    for threshold in (80, 112, 144, 176):
        yield f"threshold-{threshold}", gray.point(lambda p, t=threshold: 255 if p >= t else 0)


async def image_ocr(conn, row, analysis_id: str, label: str):
    tool = shutil.which("tesseract")
    if not tool:
        return _finish(conn, row, analysis_id, label, "tesseract is not installed in the analysis container.", status="missing", rc=127)
    try:
        image = Image.open(row["path"])
        texts = []
        with tempfile.TemporaryDirectory(prefix="ctf-ocr-") as tmp:
            for index, (name, variant) in enumerate(_ocr_variants(image)):
                if max(variant.size) < 1600:
                    variant = variant.resize((variant.width * 2, variant.height * 2))
                target = Path(tmp) / f"variant_{index}.png"
                variant.save(target)
                for psm in (6, 11):
                    argv = [tool, str(target), "stdout", "--psm", str(psm)]
                    rc, output, status = wb.run_process(argv, Path(tmp), timeout=15)
                    if status == "complete" and output.strip():
                        texts.append(f"[{name} psm={psm}]\n{output.strip()}")
        if not texts:
            return _finish(conn, row, analysis_id, label, "OCR preprocessing variants produced no readable text.")
        return _finish(conn, row, analysis_id, label, "\n\n".join(texts[:16]))
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", status="error", rc=1)


async def pyinstaller_raw(conn, row, analysis_id: str, label: str):
    try:
        data = Path(row["path"]).read_bytes()
        cookie_pos = data.rfind(PYINSTALLER_MAGIC)
        if cookie_pos < 0:
            return _finish(conn, row, analysis_id, label, "PyInstaller archive cookie was not found by raw scanning.")

        notes = [f"PyInstaller cookie located at 0x{cookie_pos:X}."]
        children = []
        pipeline = core.Pipeline(conn)
        package_start = None
        toc_pos = toc_len = None

        # Classic cookie: magic + package length + TOC position + TOC length + pyver.
        if cookie_pos + 24 <= len(data):
            try:
                pkg_len, toc_pos, toc_len, pyver = struct.unpack(">IIII", data[cookie_pos + 8:cookie_pos + 24])
                if 24 <= pkg_len <= len(data):
                    package_start = len(data) - pkg_len
                    notes.append(
                        f"Cookie fields: package_length={pkg_len}, toc_position={toc_pos}, toc_length={toc_len}, pyver={pyver}."
                    )
            except Exception:
                pass

        if package_start is None:
            # Still recover the tail region around the cookie for signature-driven recursive analysis.
            package_start = max(0, cookie_pos - min(cookie_pos, 32 * 1024 * 1024))
            notes.append("Cookie fields were not trustworthy; recovering bounded raw archive tail instead.")

        package = data[package_start:]
        if package and len(package) <= core.MAX_EXTRACTED:
            child = pipeline.process(
                package,
                "pyinstaller_package.bin",
                parent=row["id"],
                origin="derived",
                technique="Raw PyInstaller CArchive recovery",
                depth=1,
            )
            children.append(child)
            notes.append(f"Recovered package region: {child} ({len(package)} bytes).")

        if toc_pos is not None and toc_len is not None:
            absolute = package_start + toc_pos
            if 0 <= absolute < len(data) and 0 < toc_len <= core.MAX_EXTRACTED and absolute + toc_len <= len(data):
                toc = data[absolute:absolute + toc_len]
                child = pipeline.process(
                    toc,
                    "pyinstaller_toc.bin",
                    parent=row["id"],
                    origin="derived",
                    technique="Raw PyInstaller TOC recovery",
                    depth=1,
                )
                children.append(child)
                notes.append(f"Recovered TOC region: {child} ({len(toc)} bytes).")

        # PYZ archives begin with PYZ\0. Carve it independently so recursive signature/strings
        # analysis can continue even if TOC parsing is incompatible with this PyInstaller version.
        pyz = data.find(b"PYZ\x00", max(0, package_start))
        if pyz >= 0:
            blob = data[pyz:cookie_pos] if cookie_pos > pyz else data[pyz:]
            if blob and len(blob) <= core.MAX_EXTRACTED:
                child = pipeline.process(
                    blob,
                    "PYZ-raw.pyz",
                    parent=row["id"],
                    origin="derived",
                    technique=f"Raw PyInstaller PYZ carve at 0x{pyz:X}",
                    depth=1,
                )
                children.append(child)
                notes.append(f"Recovered raw PYZ candidate: {child}.")

        return _finish(conn, row, analysis_id, label, "\n".join(notes), artifacts=children)
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", status="error", rc=1, artifacts=[])


def adaptive_catalog(row):
    catalog = BASE_CATALOG(row)
    kind = row["kind"]
    suffix = Path(row["filename"]).suffix.lower()

    # Generic bounded decoding is a real autonomous capability, not a manual Decoder Lab action.
    catalog["fallback.decode-branches"] = {
        "label": "Bounded encoding / XOR branch search",
        "tool": "python",
        "argv": ["python"],
        "auto": kind in {"text", "unknown"} or suffix in {".txt", ".log", ".csv", ".dat"},
        "special": "adaptive-decode-branches",
    }

    if kind in {"pcap", "pcapng"} or suffix in {".pcap", ".pcapng"}:
        catalog["fallback.pcap-scapy"] = {
            "label": "Scapy packet parser fallback",
            "tool": "python",
            "argv": ["python"],
            "auto": False,
            "special": "adaptive-pcap-scapy",
        }

    if kind in {"png", "jpeg", "gif", "bmp"} or suffix in {".png", ".jpg", ".jpeg", ".gif", ".bmp"}:
        catalog["fallback.image-ocr"] = {
            "label": "Preprocessed OCR / visual text recovery",
            "tool": "tesseract",
            "argv": ["tesseract"],
            "auto": False,
            "special": "adaptive-image-ocr",
        }

    if kind == "pe" or suffix == ".exe":
        try:
            sample = Path(row["path"]).read_bytes()
        except OSError:
            sample = b""
        if PYINSTALLER_MAGIC in sample or any(x in sample for x in (b"pyi-python-flag", b"PyInstaller", b"PYZ-00.pyz")):
            catalog["fallback.pyinstaller-raw"] = {
                "label": "Raw PyInstaller CArchive / PYZ recovery",
                "tool": "python",
                "argv": ["python"],
                "auto": False,
                "special": "adaptive-pyinstaller-raw",
            }

    # Promote explicit alternate implementations as soon as their primary path
    # has failed, timed out, gone missing, or produced a recognized empty result.
    runs = _latest_runs(row["id"])
    promoted = set()
    for primary, fallbacks in FALLBACK_RULES.items():
        if _run_needs_fallback(runs.get(primary)):
            promoted.update(fallbacks)
    for analysis_id in promoted:
        if analysis_id in catalog:
            catalog[analysis_id]["auto"] = True
            catalog[analysis_id]["fallback_triggered"] = True

    return catalog


async def adaptive_execute(conn, row, analysis_id: str):
    catalog = adaptive_catalog(row)
    spec = catalog.get(analysis_id)
    if not spec:
        raise HTTPException(400, "Analysis is not available for this artifact type.")
    special = spec.get("special")
    label = spec["label"]
    if special == "adaptive-decode-branches":
        return await decode_branch_search(conn, row, analysis_id, label)
    if special == "adaptive-pcap-scapy":
        return await scapy_pcap(conn, row, analysis_id, label)
    if special == "adaptive-image-ocr":
        return await image_ocr(conn, row, analysis_id, label)
    if special == "adaptive-pyinstaller-raw":
        return await pyinstaller_raw(conn, row, analysis_id, label)
    return await BASE_EXECUTE(conn, row, analysis_id)


wb.analysis_catalog = adaptive_catalog
wb.execute_analysis = adaptive_execute
