from __future__ import annotations

import io
import socket
import struct
import zipfile
from collections import Counter
from pathlib import Path

from fastapi import HTTPException
from PIL import Image

from backend import main as core
from backend import workbench as wb

BASE_CATALOG = wb.analysis_catalog
BASE_EXECUTE = wb.execute_analysis
MAX_FALLBACK_CHILDREN = 40


SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", ".png", "PNG"),
    (b"\xff\xd8\xff", ".jpg", "JPEG"),
    (b"PK\x03\x04", ".zip", "ZIP"),
    (b"%PDF-", ".pdf", "PDF"),
    (b"RIFF", ".wav", "RIFF/WAV"),
    (b"MZ", ".exe", "PE"),
]


def _finish(conn, row, analysis_id: str, label: str, output: str, status: str = "complete", rc: int = 0, artifacts=None):
    output = wb.trim_output(output)
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, ["python", f"<{analysis_id}>"], output, rc, status)
    result = {
        "id": run_id,
        "analysis_id": analysis_id,
        "label": label,
        "status": status,
        "returncode": rc,
        "output": output,
        "flags": found,
    }
    if artifacts is not None:
        result["artifacts"] = artifacts
    return result


async def raw_signature_scan(conn, row, analysis_id: str, label: str):
    try:
        data = Path(row["path"]).read_bytes()
        notes = []
        children = []
        pipeline = core.Pipeline(conn)
        seen = set()

        for signature, ext, name in SIGNATURES:
            start = 0
            hits = []
            while True:
                pos = data.find(signature, start)
                if pos < 0:
                    break
                hits.append(pos)
                start = pos + 1
                if len(hits) >= 12:
                    break
            if hits:
                notes.append(f"{name} signature offsets: " + ", ".join(f"0x{x:X}" for x in hits))

            # Carve only embedded/prepended candidates, not the original file at offset 0.
            for pos in hits[:3]:
                if pos == 0 or pos in seen:
                    continue
                carved = data[pos:]
                if not carved or len(carved) > core.MAX_EXTRACTED:
                    continue
                seen.add(pos)
                child = pipeline.process(
                    carved,
                    f"raw_carve_{pos:08x}{ext}",
                    parent=row["id"],
                    origin="derived",
                    technique=f"Internal raw signature carve: {name} at 0x{pos:X}",
                    depth=1,
                )
                children.append(child)
                if len(children) >= MAX_FALLBACK_CHILDREN:
                    break

        if not notes:
            notes.append("No known embedded signatures were located by the internal raw scanner.")
        notes.append(f"Derived artifacts created: {len(children)}")
        return _finish(conn, row, analysis_id, label, "\n".join(notes), artifacts=children)
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", "error", 1, [])


async def python_archive_analysis(conn, row, analysis_id: str, label: str):
    try:
        path = Path(row["path"])
        pipeline = core.Pipeline(conn)
        children = []
        notes = []
        total = 0
        with zipfile.ZipFile(path) as zf:
            if zf.comment:
                notes.append("Archive comment: " + zf.comment.decode("utf-8", errors="replace")[:2000])
            infos = zf.infolist()
            notes.append(f"Members: {len(infos)}")
            for info in infos[:300]:
                encrypted = bool(info.flag_bits & 0x1)
                notes.append(f"- {info.filename} | {info.file_size} bytes | encrypted={encrypted}")
                if info.is_dir() or encrypted or info.file_size <= 0 or info.file_size > core.MAX_EXTRACTED:
                    continue
                if len(children) >= MAX_FALLBACK_CHILDREN or total + info.file_size > core.MAX_EXTRACTED:
                    continue
                try:
                    data = zf.read(info)
                except Exception:
                    continue
                total += len(data)
                child = pipeline.process(
                    data,
                    core.safe_filename(Path(info.filename).name or "member.bin"),
                    parent=row["id"],
                    origin="derived",
                    technique=f"Python zipfile fallback extraction: {info.filename}",
                    depth=1,
                )
                children.append(child)
        notes.append(f"Fallback-extracted artifacts: {len(children)}")
        return _finish(conn, row, analysis_id, label, "\n".join(notes), artifacts=children)
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", "error", 1, [])


def _pack_lsb(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


async def internal_image_lsb(conn, row, analysis_id: str, label: str):
    try:
        image = Image.open(row["path"]).convert("RGBA")
        pixels = list(image.getdata())
        reports = [f"Image: {image.width}x{image.height} RGBA"]
        for channel, name in enumerate(("R", "G", "B", "A")):
            bits = [(px[channel] & 1) for px in pixels]
            raw = _pack_lsb(bits)
            strings = core.strings(raw[:2 * 1024 * 1024], 4)[:80]
            reports.append(f"\n{name}-channel LSB bytes: {len(raw)}")
            if strings:
                reports.append("Printable LSB strings:\n" + "\n".join(strings[:30]))
        return _finish(conn, row, analysis_id, label, "\n".join(reports))
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", "error", 1)


async def dpkt_pcap_analysis(conn, row, analysis_id: str, label: str):
    try:
        import dpkt

        path = Path(row["path"])
        counts = Counter()
        endpoints = Counter()
        payload_strings = []
        packets = 0
        with path.open("rb") as handle:
            try:
                reader = dpkt.pcap.Reader(handle)
            except Exception:
                handle.seek(0)
                reader = dpkt.pcapng.Reader(handle)
            for _, buf in reader:
                packets += 1
                if packets > 200000:
                    break
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        continue
                    src = socket.inet_ntop(socket.AF_INET6 if isinstance(ip, dpkt.ip6.IP6) else socket.AF_INET, ip.src)
                    dst = socket.inet_ntop(socket.AF_INET6 if isinstance(ip, dpkt.ip6.IP6) else socket.AF_INET, ip.dst)
                    endpoints[(src, dst)] += 1
                    trans = ip.data
                    if isinstance(trans, dpkt.tcp.TCP):
                        counts["TCP"] += 1
                        payload = bytes(trans.data)
                    elif isinstance(trans, dpkt.udp.UDP):
                        counts["UDP"] += 1
                        payload = bytes(trans.data)
                        if trans.sport == 53 or trans.dport == 53:
                            counts["DNS"] += 1
                    elif isinstance(trans, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                        counts["ICMP"] += 1
                        payload = bytes(trans.data)
                    else:
                        payload = b""
                    if payload and len(payload_strings) < 250:
                        text = "\n".join(core.strings(payload, 4)[:10])
                        if text:
                            payload_strings.append(text)
                except Exception:
                    continue

        out = [f"Packets parsed: {packets}", "Protocol counts: " + ", ".join(f"{k}={v}" for k, v in counts.most_common())]
        out.append("Top endpoint pairs:")
        out.extend(f"- {a} -> {b}: {n}" for (a, b), n in endpoints.most_common(30))
        if payload_strings:
            out.append("\nPrintable payload evidence:\n" + "\n---\n".join(payload_strings[:120]))
        return _finish(conn, row, analysis_id, label, "\n".join(out))
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", "error", 1)


async def python_pe_analysis(conn, row, analysis_id: str, label: str):
    try:
        import pefile

        path = Path(row["path"])
        pe = pefile.PE(str(path), fast_load=False)
        out = [f"Machine: 0x{pe.FILE_HEADER.Machine:04X}", f"Sections: {pe.FILE_HEADER.NumberOfSections}"]
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            out.append(
                f"Section {name}: VA=0x{section.VirtualAddress:X} raw={section.SizeOfRawData} entropy={section.get_entropy():.3f}"
            )
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:80]:
                dll = entry.dll.decode("ascii", errors="replace")
                names = []
                for imp in entry.imports[:80]:
                    names.append(imp.name.decode("ascii", errors="replace") if imp.name else f"ord:{imp.ordinal}")
                imports.append(f"{dll}: " + ", ".join(names))
        if imports:
            out.append("Imports:\n" + "\n".join(imports))

        children = []
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            data = path.read_bytes()[overlay_offset:]
            out.append(f"Overlay: offset=0x{overlay_offset:X} size={len(data)}")
            if data and len(data) <= core.MAX_EXTRACTED:
                child = core.Pipeline(conn).process(
                    data,
                    "pe_overlay.bin",
                    parent=row["id"],
                    origin="derived",
                    technique=f"pefile fallback overlay extraction at 0x{overlay_offset:X}",
                    depth=1,
                )
                children.append(child)
        return _finish(conn, row, analysis_id, label, "\n".join(out), artifacts=children)
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", "error", 1, [])


async def python_pdf_analysis(conn, row, analysis_id: str, label: str):
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(Path(row["path"])))
        out = [f"Pages: {len(reader.pages)}", f"Metadata: {reader.metadata}"]
        for index, page in enumerate(reader.pages[:30]):
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            if text.strip():
                out.append(f"\n--- page {index + 1} ---\n{text[:12000]}")
        return _finish(conn, row, analysis_id, label, "\n".join(out))
    except Exception as exc:
        return _finish(conn, row, analysis_id, label, f"{type(exc).__name__}: {exc}", "error", 1)


def fallback_catalog(row):
    catalog = BASE_CATALOG(row)
    kind = row["kind"]
    suffix = Path(row["filename"]).suffix.lower()

    catalog["fallback.raw-signature-scan"] = {
        "label": "Internal raw signature scan / carve",
        "tool": "python",
        "argv": ["python"],
        "auto": False,
        "special": "fallback-raw-signatures",
    }

    if kind in {"zip", "docx", "xlsx", "pptx"} or suffix in {".zip", ".docx", ".xlsx", ".pptx"}:
        catalog["fallback.python-archive"] = {
            "label": "Python archive parser / extractor",
            "tool": "python",
            "argv": ["python"],
            "auto": False,
            "special": "fallback-python-archive",
        }

    if kind in {"png", "jpeg", "gif", "bmp"} or suffix in {".png", ".jpg", ".jpeg", ".gif", ".bmp"}:
        catalog["fallback.image-lsb"] = {
            "label": "Internal image LSB channel analysis",
            "tool": "python",
            "argv": ["python"],
            "auto": False,
            "special": "fallback-image-lsb",
        }

    if kind in {"pcap", "pcapng"} or suffix in {".pcap", ".pcapng"}:
        catalog["fallback.pcap-dpkt"] = {
            "label": "DPKT packet parser fallback",
            "tool": "python",
            "argv": ["python"],
            "auto": False,
            "special": "fallback-pcap-dpkt",
        }

    if kind == "pe" or suffix == ".exe":
        catalog["fallback.pefile"] = {
            "label": "Python PE parser / overlay recovery",
            "tool": "python",
            "argv": ["python"],
            "auto": False,
            "special": "fallback-pefile",
        }

    if kind == "pdf" or suffix == ".pdf":
        catalog["fallback.pypdf"] = {
            "label": "Python PDF parser fallback",
            "tool": "python",
            "argv": ["python"],
            "auto": False,
            "special": "fallback-pypdf",
        }

    return catalog


async def fallback_execute(conn, row, analysis_id: str):
    catalog = fallback_catalog(row)
    spec = catalog.get(analysis_id)
    if not spec:
        raise HTTPException(400, "Analysis is not available for this artifact type.")
    special = spec.get("special")
    label = spec["label"]
    if special == "fallback-raw-signatures":
        return await raw_signature_scan(conn, row, analysis_id, label)
    if special == "fallback-python-archive":
        return await python_archive_analysis(conn, row, analysis_id, label)
    if special == "fallback-image-lsb":
        return await internal_image_lsb(conn, row, analysis_id, label)
    if special == "fallback-pcap-dpkt":
        return await dpkt_pcap_analysis(conn, row, analysis_id, label)
    if special == "fallback-pefile":
        return await python_pe_analysis(conn, row, analysis_id, label)
    if special == "fallback-pypdf":
        return await python_pdf_analysis(conn, row, analysis_id, label)
    return await BASE_EXECUTE(conn, row, analysis_id)


wb.analysis_catalog = fallback_catalog
wb.execute_analysis = fallback_execute
