from __future__ import annotations

import re
import shutil
from pathlib import Path

from fastapi import HTTPException

from backend import main as core
from backend import workbench as wb


# This module is imported after the Hack4Gov analyzer pack, so extend the
# fully-patched catalog rather than replacing any existing capability.
BASE_CATALOG = wb.analysis_catalog
BASE_EXECUTE = wb.execute_analysis

MAX_PYI_IMPORTS = 30
MAX_PYI_IMPORT_BYTES = 32 * 1024 * 1024

PYINSTALLER_MARKERS = (
    b"pyi-python-flag",
    b"PyInstaller",
    b"PYZ-00.pyz",
    b"pyiboot01_bootstrap",
    b"_MEIPASS",
    b"MEI\x0c\x0b\x0a\x0b\x0e",
)


def looks_like_pyinstaller(row) -> bool:
    if row["kind"] not in {"pe", "elf"} and Path(row["filename"]).suffix.lower() not in {".exe", ".bin"}:
        return False
    try:
        data = Path(row["path"]).read_bytes()
    except OSError:
        return False
    return any(marker in data for marker in PYINSTALLER_MARKERS)


def _import_priority(path: Path, entrypoints: set[str]) -> tuple[int, int, str]:
    name = path.name
    suffix = path.suffix.lower()
    if name in entrypoints:
        rank = 0
    elif suffix == ".py":
        rank = 1
    elif suffix == ".pyc":
        rank = 2
    elif suffix in {".txt", ".json", ".ini", ".cfg", ".yaml", ".yml", ".xml"}:
        rank = 3
    elif suffix in {".wav", ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".html", ".css", ".js"}:
        rank = 4
    else:
        rank = 9
    try:
        size = path.stat().st_size
    except OSError:
        size = 1 << 60
    return rank, size, path.as_posix()


async def pyinstaller_extract(conn, row, analysis_id: str, label: str):
    tool = shutil.which("pyinstxtractor-ng") or shutil.which("pyinstxtractor")
    argv = [tool or "pyinstxtractor-ng", str(Path(row["path"]))]
    if not tool:
        output = "PyInstaller extractor is not installed in the analysis container."
        run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    source = Path(row["path"])
    outdir = source.parent / f"{source.name}_extracted"
    shutil.rmtree(outdir, ignore_errors=True)

    rc, process_output, status = wb.run_process(argv, source.parent, timeout=90)

    if not outdir.is_dir():
        matches = [p for p in source.parent.glob(f"{source.name}*_extracted") if p.is_dir()]
        if matches:
            outdir = max(matches, key=lambda p: p.stat().st_mtime)

    entrypoints = set(re.findall(r"(?im)Possible entry point:\s*([^\r\n]+)", process_output or ""))
    entrypoints = {Path(x.strip()).name for x in entrypoints if x.strip()}

    pipeline = core.Pipeline(conn)
    imported: list[str] = []
    imported_names: list[str] = []
    total_bytes = 0

    if outdir.is_dir():
        candidates = [p for p in outdir.rglob("*") if p.is_file()]
        candidates.sort(key=lambda p: _import_priority(p, entrypoints))

        for candidate in candidates:
            if len(imported) >= MAX_PYI_IMPORTS:
                break
            try:
                size = candidate.stat().st_size
            except OSError:
                continue
            if size <= 0 or size > core.MAX_EXTRACTED:
                continue
            suffix = candidate.suffix.lower()
            if suffix in {".dll", ".pyd", ".so", ".dylib", ".a", ".lib"}:
                continue
            if _import_priority(candidate, entrypoints)[0] >= 9 and size > 512 * 1024:
                continue
            if total_bytes + size > MAX_PYI_IMPORT_BYTES:
                continue
            try:
                data = candidate.read_bytes()
            except OSError:
                continue

            rel = candidate.relative_to(outdir).as_posix()
            child = pipeline.process(
                data,
                core.safe_filename(candidate.name),
                parent=row["id"],
                origin="derived",
                technique=f"PyInstaller extraction: {rel}",
                depth=1,
            )
            imported.append(child)
            imported_names.append(f"{child} {rel}")
            total_bytes += size

    notes = [process_output.strip() if process_output else "PyInstaller extraction completed."]
    notes.append(f"Imported {len(imported)} extracted code/resource artifact(s), {total_bytes:,} bytes total.")
    if entrypoints:
        notes.append("Possible entry point(s): " + ", ".join(sorted(entrypoints)))
    if imported_names:
        notes.append("Imported artifacts:\n" + "\n".join(imported_names[:60]))
    output = wb.trim_output("\n\n".join(notes))
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, output, rc, status)
    return {
        "id": run_id,
        "analysis_id": analysis_id,
        "label": label,
        "status": status,
        "returncode": rc,
        "output": output,
        "artifacts": imported,
        "flags": found,
    }


async def pyc_disassemble(conn, row, analysis_id: str, label: str):
    tool = shutil.which("pydisasm")
    argv = [tool or "pydisasm", "-S", "-F", "extended", str(Path(row["path"]))]
    if not tool:
        output = "pydisasm/xdis is not installed in the analysis container."
        run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    rc, output, status = wb.run_process(argv, Path(row["path"]).parent, timeout=45)
    output = wb.trim_output(output)
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, argv, output, rc, status)
    return {
        "id": run_id,
        "analysis_id": analysis_id,
        "label": label,
        "status": status,
        "returncode": rc,
        "output": output,
        "flags": found,
    }


def deep_binary_catalog(row):
    catalog = BASE_CATALOG(row)
    suffix = Path(row["filename"]).suffix.lower()

    if looks_like_pyinstaller(row):
        catalog["binary.pyinstaller-extract"] = {
            "label": "Extract PyInstaller application",
            "tool": "pyinstxtractor-ng",
            "argv": ["pyinstxtractor-ng"],
            "auto": True,
            "special": "deep-pyinstaller",
        }

    if suffix == ".pyc":
        catalog["python.bytecode-disassembly"] = {
            "label": "Cross-version Python bytecode disassembly",
            "tool": "pydisasm",
            "argv": ["pydisasm"],
            "auto": True,
            "special": "deep-pyc-disasm",
        }

    return catalog


async def deep_binary_execute(conn, row, analysis_id: str):
    catalog = deep_binary_catalog(row)
    spec = catalog.get(analysis_id)
    if not spec:
        raise HTTPException(400, "Analysis is not available for this artifact type.")
    special = spec.get("special")
    if special == "deep-pyinstaller":
        return await pyinstaller_extract(conn, row, analysis_id, spec["label"])
    if special == "deep-pyc-disasm":
        return await pyc_disassemble(conn, row, analysis_id, spec["label"])
    return await BASE_EXECUTE(conn, row, analysis_id)


wb.analysis_catalog = deep_binary_catalog
wb.execute_analysis = deep_binary_execute

# Chain the audio signal extension after the deep-binary patch so WAV artifacts
# produced or uploaded later gain automatic tone/grid decoding as well.
from backend import audio_signal as audio_signal  # noqa: E402,F401
