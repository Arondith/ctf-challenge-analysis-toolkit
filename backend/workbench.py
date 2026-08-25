from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from backend import main as core


# ============================================================
# Workbench configuration
# ============================================================

TOOL_TIMEOUT = int(os.getenv("CTF_TOOL_TIMEOUT", "25"))
MAX_TOOL_OUTPUT = int(os.getenv("CTF_MAX_TOOL_OUTPUT", "200000"))
MAX_STREAMS = int(os.getenv("CTF_MAX_TCP_STREAMS", "96"))
MAX_EXPORTED_OBJECTS = int(os.getenv("CTF_MAX_EXPORTED_OBJECTS", "40"))


def ensure_workbench_db() -> None:
    with core.db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS tool_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT NOT NULL,
                analysis_id TEXT NOT NULL,
                label TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                returncode INTEGER,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tool_runs_artifact
            ON tool_runs(artifact_id, id DESC);
            """
        )


ensure_workbench_db()


# ============================================================
# Safe execution helpers
# ============================================================


def artifact_row(conn, artifact_id: str):
    row = conn.execute(
        "SELECT * FROM artifacts WHERE id=?",
        (artifact_id,),
    ).fetchone()

    if not row:
        raise HTTPException(404, "Artifact not found.")

    path = Path(row["path"])

    if not path.is_file():
        raise HTTPException(404, "Artifact data missing.")

    return row


def trim_output(data: bytes | str | None) -> str:
    if data is None:
        return ""

    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data

    if len(text) <= MAX_TOOL_OUTPUT:
        return text

    omitted = len(text) - MAX_TOOL_OUTPUT
    return text[:MAX_TOOL_OUTPUT] + f"\n\n[output truncated: {omitted:,} characters omitted]"


def command_display(argv: list[str]) -> str:
    def quote(value: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9_./:=+,-]+", value):
            return value
        return "'" + value.replace("'", "'\\''") + "'"

    return " ".join(quote(x) for x in argv)


def run_process(argv: list[str], cwd: Path | None = None, timeout: int | None = None):
    env = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/tmp",
    }

    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout or TOOL_TIMEOUT,
            check=False,
        )
        return completed.returncode, trim_output(completed.stdout), "complete"

    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or b""
        output = trim_output(partial)
        output += f"\n\n[stopped after {timeout or TOOL_TIMEOUT}s timeout]"
        return 124, output, "timeout"

    except Exception as exc:
        return 1, f"{type(exc).__name__}: {exc}", "error"


def record_run(
    conn,
    artifact_id: str,
    analysis_id: str,
    label: str,
    argv: list[str],
    output: str,
    returncode: int,
    status: str,
):
    cursor = conn.execute(
        """
        INSERT INTO tool_runs(
            artifact_id,
            analysis_id,
            label,
            command,
            output,
            returncode,
            status,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            artifact_id,
            analysis_id,
            label,
            command_display(argv),
            output,
            returncode,
            status,
            core.now(),
        ),
    )

    core.add_event(
        conn,
        artifact_id,
        f"Workbench: {label}",
        status,
    )

    return cursor.lastrowid


def insert_flags_from_text(conn, row, text: str, technique: str):
    pipeline = core.Pipeline(conn)
    chain = pipeline.technique_chain(row["id"])
    full_technique = f"{chain} → {technique}" if chain else technique
    added = []

    for flag, confidence in core.detect_flags(text.encode("utf-8", errors="ignore")):
        exists = conn.execute(
            "SELECT id FROM flags WHERE artifact_id=? AND flag=?",
            (row["id"], flag),
        ).fetchone()

        if exists:
            continue

        conn.execute(
            """
            INSERT INTO flags(
                artifact_id,
                flag,
                source,
                technique,
                confidence,
                status
            ) VALUES (?, ?, ?, ?, ?, 'possible')
            """,
            (
                row["id"],
                flag,
                row["filename"],
                full_technique,
                confidence,
            ),
        )

        core.add_event(conn, row["id"], "Possible flag found", flag)
        added.append(flag)

    return added


# ============================================================
# Analysis catalog
# ============================================================


def analysis_catalog(row):
    path = str(Path(row["path"]))
    kind = row["kind"]

    catalog = {
        "file.identity": {
            "label": "File identification",
            "tool": "file",
            "argv": ["file", "-b", "--mime", path],
            "auto": True,
        },
        "file.strings": {
            "label": "Printable strings",
            "tool": "strings",
            "argv": ["strings", "-a", "-n", "4", path],
            "auto": True,
        },
        "file.hex": {
            "label": "Hex preview",
            "tool": "xxd",
            "argv": ["xxd", "-g", "1", "-l", "8192", path],
            "auto": True,
        },
        "file.binwalk": {
            "label": "Binwalk signature scan",
            "tool": "binwalk",
            "argv": ["binwalk", path],
            "auto": True,
        },
        "file.exif": {
            "label": "Metadata / EXIF",
            "tool": "exiftool",
            "argv": ["exiftool", "-G1", "-a", "-s", path],
            "auto": kind in {"png", "jpeg", "gif", "bmp", "pdf", "wav", "docx", "xlsx", "pptx"},
        },
    }

    if kind in {"png", "bmp"}:
        catalog["image.zsteg"] = {
            "label": "Image bit-plane / zsteg scan",
            "tool": "zsteg",
            "argv": ["zsteg", "-a", path],
            "auto": True,
        }

    if kind in {"jpeg", "bmp", "wav"}:
        catalog["stego.steghide"] = {
            "label": "Steghide container info",
            "tool": "steghide",
            "argv": ["steghide", "info", "-sf", path, "-p", ""],
            "auto": True,
        }

    if kind in {"zip", "docx", "xlsx", "pptx"}:
        catalog["archive.list"] = {
            "label": "Archive member list",
            "tool": "unzip",
            "argv": ["unzip", "-l", path],
            "auto": True,
        }

    if kind in {"elf", "pe"}:
        catalog["binary.rabin2"] = {
            "label": "Binary headers / imports / symbols",
            "tool": "rabin2",
            "argv": ["rabin2", "-I", "-i", "-s", path],
            "auto": True,
        }
        catalog["binary.radare2"] = {
            "label": "Radare2 static summary",
            "tool": "radare2",
            "argv": ["radare2", "-2", "-q", "-c", "iI;ii;is;iz", path],
            "auto": True,
        }
        catalog["binary.objdump"] = {
            "label": "Objdump headers",
            "tool": "objdump",
            "argv": ["objdump", "-x", path],
            "auto": True,
        }
        catalog["binary.nm"] = {
            "label": "Symbol table",
            "tool": "nm",
            "argv": ["nm", "-a", path],
            "auto": True,
        }
        catalog["binary.upx"] = {
            "label": "UPX packed-file test",
            "tool": "upx",
            "argv": ["upx", "-t", path],
            "auto": True,
        }

        if kind == "elf":
            catalog["binary.readelf"] = {
                "label": "ELF headers / sections / symbols",
                "tool": "readelf",
                "argv": ["readelf", "-h", "-S", "-s", path],
                "auto": True,
            }

    if kind in {"pcap", "pcapng"}:
        catalog.update(
            {
                "pcap.protocols": {
                    "label": "PCAP protocol hierarchy",
                    "tool": "tshark",
                    "argv": ["tshark", "-r", path, "-q", "-z", "io,phs"],
                    "auto": True,
                },
                "pcap.endpoints": {
                    "label": "PCAP IP endpoints",
                    "tool": "tshark",
                    "argv": ["tshark", "-r", path, "-q", "-z", "endpoints,ip"],
                    "auto": True,
                },
                "pcap.conversations": {
                    "label": "PCAP TCP conversations",
                    "tool": "tshark",
                    "argv": ["tshark", "-r", path, "-q", "-z", "conv,tcp"],
                    "auto": True,
                },
                "pcap.dns": {
                    "label": "DNS queries",
                    "tool": "tshark",
                    "argv": [
                        "tshark", "-r", path,
                        "-Y", "dns.qry.name",
                        "-T", "fields",
                        "-e", "frame.number",
                        "-e", "ip.src",
                        "-e", "ip.dst",
                        "-e", "dns.qry.name",
                    ],
                    "auto": True,
                },
                "pcap.http": {
                    "label": "HTTP requests",
                    "tool": "tshark",
                    "argv": [
                        "tshark", "-r", path,
                        "-Y", "http.request",
                        "-T", "fields",
                        "-e", "frame.number",
                        "-e", "ip.src",
                        "-e", "ip.dst",
                        "-e", "http.request.method",
                        "-e", "http.host",
                        "-e", "http.request.uri",
                    ],
                    "auto": True,
                },
                "pcap.data": {
                    "label": "Packet payload strings",
                    "tool": "tshark",
                    "argv": [
                        "tshark", "-r", path,
                        "-T", "fields",
                        "-e", "data.text",
                        "-e", "tcp.payload",
                        "-e", "udp.payload",
                    ],
                    "auto": True,
                },
            }
        )

    catalog["deep.foremost"] = {
        "label": "Deep file carving (Foremost)",
        "tool": "foremost",
        "argv": ["foremost"],
        "auto": False,
        "special": "foremost",
    }

    if kind in {"pcap", "pcapng"}:
        catalog["pcap.stream-scan"] = {
            "label": "Reassemble and scan TCP streams",
            "tool": "tshark",
            "argv": ["tshark"],
            "auto": True,
            "special": "stream-scan",
        }
        catalog["pcap.export-objects"] = {
            "label": "Extract transferred network objects",
            "tool": "tshark",
            "argv": ["tshark"],
            "auto": True,
            "special": "export-objects",
        }

    return catalog


# ============================================================
# Special analyzers
# ============================================================


def parse_hex_payload_lines(text: str) -> bytes:
    chunks = []

    for line in text.splitlines():
        for token in re.split(r"[\t, ]+", line.strip()):
            token = token.strip().replace(":", "")
            if len(token) >= 2 and len(token) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", token):
                try:
                    chunks.append(bytes.fromhex(token))
                except ValueError:
                    pass

    return b"".join(chunks)


async def stream_scan(conn, row, analysis_id: str, label: str):
    tshark = shutil.which("tshark")
    if not tshark:
        argv = ["tshark"]
        output = "tshark is not installed in the analysis container."
        run_id = record_run(conn, row["id"], analysis_id, label, argv, output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    path = str(Path(row["path"]))
    list_argv = [tshark, "-r", path, "-T", "fields", "-e", "tcp.stream"]
    rc, stream_text, status = await asyncio.to_thread(run_process, list_argv)

    stream_ids = []
    for value in stream_text.splitlines():
        value = value.strip()
        if value.isdigit() and value not in stream_ids:
            stream_ids.append(value)
        if len(stream_ids) >= MAX_STREAMS:
            break

    notes = [f"TCP streams discovered: {len(stream_ids)}"]
    found = []

    for stream_id in stream_ids:
        argv = [
            tshark, "-r", path,
            "-Y", f"tcp.stream=={stream_id}",
            "-T", "fields",
            "-e", "tcp.payload",
        ]
        _, payload_text, _ = await asyncio.to_thread(run_process, argv, None, min(TOOL_TIMEOUT, 12))
        payload = parse_hex_payload_lines(payload_text)

        if not payload:
            continue

        flags = core.detect_flags(payload)
        if flags:
            printable = "\n".join(core.strings(payload, 4)[:80])
            notes.append(f"\n--- stream {stream_id} ---\n{printable}")

            pipeline = core.Pipeline(conn)
            chain = pipeline.technique_chain(row["id"])
            technique = f"{chain} → tshark TCP stream {stream_id}" if chain else f"tshark TCP stream {stream_id}"

            for flag, confidence in flags:
                exists = conn.execute(
                    "SELECT id FROM flags WHERE artifact_id=? AND flag=?",
                    (row["id"], flag),
                ).fetchone()
                if exists:
                    continue

                conn.execute(
                    """
                    INSERT INTO flags(artifact_id, flag, source, technique, confidence, status)
                    VALUES (?, ?, ?, ?, ?, 'possible')
                    """,
                    (row["id"], flag, row["filename"], technique, confidence),
                )
                core.add_event(conn, row["id"], "Possible flag found", flag)
                found.append(flag)

    if found:
        notes.insert(1, "Flag candidates from reconstructed streams: " + ", ".join(found))

    output = trim_output("\n".join(notes))
    argv = [tshark, "-r", path, "<reassemble TCP streams>"]
    final_status = "complete" if status != "error" else status
    run_id = record_run(conn, row["id"], analysis_id, label, argv, output, rc, final_status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": final_status, "output": output, "flags": found}


async def export_network_objects(conn, row, analysis_id: str, label: str):
    tshark = shutil.which("tshark")
    if not tshark:
        argv = ["tshark"]
        output = "tshark is not installed in the analysis container."
        run_id = record_run(conn, row["id"], analysis_id, label, argv, output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    artifact_dir = Path(row["path"]).parent
    export_root = artifact_dir / "workbench_exports"
    shutil.rmtree(export_root, ignore_errors=True)
    export_root.mkdir(parents=True, exist_ok=True)

    processed = []
    messages = []
    protocols = ["http", "tftp", "smb", "imf"]
    total_bytes = 0

    pipeline = core.Pipeline(conn)

    for protocol in protocols:
        outdir = export_root / protocol
        outdir.mkdir(parents=True, exist_ok=True)

        argv = [tshark, "-r", str(Path(row["path"])), "--export-objects", f"{protocol},{outdir}"]
        rc, output, status = await asyncio.to_thread(run_process, argv, artifact_dir, min(TOOL_TIMEOUT, 20))

        if output.strip():
            messages.append(f"[{protocol}] {output.strip()}")

        if rc not in {0, 1} and status != "complete":
            continue

        for candidate in sorted(outdir.rglob("*")):
            if not candidate.is_file():
                continue
            if len(processed) >= MAX_EXPORTED_OBJECTS:
                break

            try:
                size = candidate.stat().st_size
            except OSError:
                continue

            if size <= 0 or size > core.MAX_EXTRACTED:
                continue
            if total_bytes + size > core.MAX_EXTRACTED:
                break

            try:
                data = candidate.read_bytes()
            except OSError:
                continue

            total_bytes += len(data)
            child_id = pipeline.process(
                data,
                core.safe_filename(candidate.name),
                parent=row["id"],
                origin="derived",
                technique=f"tshark {protocol.upper()} object export",
                depth=1,
            )
            processed.append(child_id)

    output = f"Extracted {len(processed)} network object(s)."
    if processed:
        output += "\nArtifacts: " + ", ".join(processed)
    if messages:
        output += "\n\n" + "\n".join(messages)

    argv = [tshark, "-r", str(Path(row["path"])), "--export-objects", "http/tftp/smb/imf"]
    run_id = record_run(conn, row["id"], analysis_id, label, argv, trim_output(output), 0, "complete")
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "complete", "output": trim_output(output), "artifacts": processed}


async def foremost_carve(conn, row, analysis_id: str, label: str):
    foremost = shutil.which("foremost")
    if not foremost:
        argv = ["foremost"]
        output = "foremost is not installed in the analysis container."
        run_id = record_run(conn, row["id"], analysis_id, label, argv, output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": "missing", "output": output}

    artifact_dir = Path(row["path"]).parent
    outdir = artifact_dir / "foremost_output"
    shutil.rmtree(outdir, ignore_errors=True)
    argv = [foremost, "-Q", "-i", str(Path(row["path"])), "-o", str(outdir)]
    rc, process_output, status = await asyncio.to_thread(run_process, argv, artifact_dir, min(TOOL_TIMEOUT * 2, 60))

    pipeline = core.Pipeline(conn)
    processed = []
    total_bytes = 0

    if outdir.exists():
        for candidate in sorted(outdir.rglob("*")):
            if not candidate.is_file() or candidate.name == "audit.txt":
                continue
            if len(processed) >= MAX_EXPORTED_OBJECTS:
                break

            try:
                size = candidate.stat().st_size
            except OSError:
                continue

            if size <= 0 or size > core.MAX_EXTRACTED or total_bytes + size > core.MAX_EXTRACTED:
                continue

            try:
                data = candidate.read_bytes()
            except OSError:
                continue

            total_bytes += len(data)
            child_id = pipeline.process(
                data,
                core.safe_filename(candidate.name),
                parent=row["id"],
                origin="derived",
                technique="Foremost file carving",
                depth=1,
            )
            processed.append(child_id)

    output = process_output
    output += f"\n\nImported {len(processed)} carved object(s) into the artifact graph."
    if processed:
        output += "\nArtifacts: " + ", ".join(processed)

    run_id = record_run(conn, row["id"], analysis_id, label, argv, trim_output(output), rc, status)
    return {"id": run_id, "analysis_id": analysis_id, "label": label, "status": status, "output": trim_output(output), "artifacts": processed}


async def execute_analysis(conn, row, analysis_id: str):
    catalog = analysis_catalog(row)
    spec = catalog.get(analysis_id)

    if not spec:
        raise HTTPException(400, "Analysis is not available for this artifact type.")

    special = spec.get("special")
    if special == "stream-scan":
        return await stream_scan(conn, row, analysis_id, spec["label"])
    if special == "export-objects":
        return await export_network_objects(conn, row, analysis_id, spec["label"])
    if special == "foremost":
        return await foremost_carve(conn, row, analysis_id, spec["label"])

    tool = shutil.which(spec["tool"])
    argv = list(spec["argv"])

    if not tool:
        output = f"{spec['tool']} is not installed in the analysis container."
        run_id = record_run(conn, row["id"], analysis_id, spec["label"], argv, output, 127, "missing")
        return {"id": run_id, "analysis_id": analysis_id, "label": spec["label"], "status": "missing", "output": output}

    argv[0] = tool
    rc, output, status = await asyncio.to_thread(run_process, argv, Path(row["path"]).parent)
    found = insert_flags_from_text(conn, row, output, spec["label"])
    run_id = record_run(conn, row["id"], analysis_id, spec["label"], argv, output, rc, status)

    return {
        "id": run_id,
        "analysis_id": analysis_id,
        "label": spec["label"],
        "status": status,
        "returncode": rc,
        "output": output,
        "flags": found,
    }


# ============================================================
# Demo/session helpers
# ============================================================


def recursive_demo_ids(conn):
    rows = conn.execute(
        """
        WITH RECURSIVE demo_tree(id) AS (
            SELECT id FROM artifacts WHERE origin='demo'
            UNION
            SELECT e.child_id
            FROM edges e
            JOIN demo_tree d ON e.parent_id=d.id
        )
        SELECT DISTINCT id FROM demo_tree
        """
    ).fetchall()
    return [x["id"] for x in rows]


def delete_artifacts(conn, ids: list[str]):
    if not ids:
        return 0

    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT path FROM artifacts WHERE id IN ({placeholders})",
        ids,
    ).fetchall()

    conn.execute(f"DELETE FROM tool_runs WHERE artifact_id IN ({placeholders})", ids)
    conn.execute(f"DELETE FROM findings WHERE artifact_id IN ({placeholders})", ids)
    conn.execute(f"DELETE FROM flags WHERE artifact_id IN ({placeholders})", ids)
    conn.execute(f"DELETE FROM events WHERE artifact_id IN ({placeholders})", ids)
    conn.execute(f"DELETE FROM edges WHERE parent_id IN ({placeholders}) OR child_id IN ({placeholders})", ids + ids)
    conn.execute(f"DELETE FROM artifacts WHERE id IN ({placeholders})", ids)

    for row in rows:
        try:
            shutil.rmtree(Path(row["path"]).parent, ignore_errors=True)
        except Exception:
            pass

    return len(ids)


# ============================================================
# Outer FastAPI application
# ============================================================

app = FastAPI(
    title="H4G CTF Analysis Workbench",
    version="0.2.0",
    description="Integrated local/authorized CTF artifact analysis workbench.",
)


@app.get("/api/workbench/health")
def workbench_health():
    return {
        "status": "ok",
        "mode": "integrated-workbench",
        "tool_timeout": TOOL_TIMEOUT,
        "max_output": MAX_TOOL_OUTPUT,
    }


@app.get("/api/workbench/artifacts/{artifact_id}/available")
def available_analyses(artifact_id: str):
    with core.db() as conn:
        row = artifact_row(conn, artifact_id)
        catalog = analysis_catalog(row)
        return [
            {
                "id": analysis_id,
                "label": spec["label"],
                "tool": spec["tool"],
                "auto": bool(spec.get("auto")),
                "available": shutil.which(spec["tool"]) is not None,
            }
            for analysis_id, spec in catalog.items()
        ]


@app.get("/api/workbench/artifacts/{artifact_id}/runs")
def analysis_runs(artifact_id: str):
    with core.db() as conn:
        artifact_row(conn, artifact_id)
        rows = conn.execute(
            "SELECT * FROM tool_runs WHERE artifact_id=? ORDER BY id DESC LIMIT 100",
            (artifact_id,),
        ).fetchall()
        return [dict(x) for x in rows]


@app.get("/api/workbench/artifacts/{artifact_id}/preview")
def artifact_preview(artifact_id: str):
    with core.db() as conn:
        row = artifact_row(conn, artifact_id)
        data = Path(row["path"]).read_bytes()

    sample = data[:32768]
    text = sample.decode("utf-8", errors="replace") if core.printable_ratio(sample) > 0.55 else ""
    string_list = core.strings(data[:1024 * 1024], 4)[:300]

    hex_lines = []
    for offset in range(0, min(len(data), 4096), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        hex_lines.append(f"{offset:08x}  {hex_part:<47}  |{ascii_part}|")

    return {
        "artifact_id": artifact_id,
        "text": trim_output(text),
        "strings": string_list,
        "hex": "\n".join(hex_lines),
    }


@app.post("/api/workbench/artifacts/{artifact_id}/run/{analysis_id}")
async def run_one(artifact_id: str, analysis_id: str):
    with core.db() as conn:
        row = artifact_row(conn, artifact_id)
        result = await execute_analysis(conn, row, analysis_id)
        conn.commit()

    await core.hub.broadcast({"event": "workbench-analysis", "artifact_id": artifact_id})
    return result


@app.post("/api/workbench/artifacts/{artifact_id}/run-all")
async def run_all(artifact_id: str):
    results = []

    with core.db() as conn:
        row = artifact_row(conn, artifact_id)
        catalog = analysis_catalog(row)

        for analysis_id, spec in catalog.items():
            if not spec.get("auto"):
                continue
            try:
                results.append(await execute_analysis(conn, row, analysis_id))
            except Exception as exc:
                results.append(
                    {
                        "analysis_id": analysis_id,
                        "label": spec["label"],
                        "status": "error",
                        "output": f"{type(exc).__name__}: {exc}",
                    }
                )

        conn.commit()

    await core.hub.broadcast({"event": "workbench-analysis", "artifact_id": artifact_id})
    return {"artifact_id": artifact_id, "results": results}


@app.get("/api/workbench/flags")
def workbench_flags(include_demo: bool = False):
    with core.db() as conn:
        if include_demo:
            rows = conn.execute("SELECT * FROM flags ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                """
                WITH RECURSIVE demo_tree(id) AS (
                    SELECT id FROM artifacts WHERE origin='demo'
                    UNION
                    SELECT e.child_id
                    FROM edges e
                    JOIN demo_tree d ON e.parent_id=d.id
                )
                SELECT f.*
                FROM flags f
                WHERE f.artifact_id NOT IN (SELECT id FROM demo_tree)
                ORDER BY f.id DESC
                """
            ).fetchall()
        return [dict(x) for x in rows]


@app.post("/api/workbench/clear-demo")
def clear_demo():
    with core.db() as conn:
        ids = recursive_demo_ids(conn)
        removed = delete_artifacts(conn, ids)
        conn.commit()
    return {"ok": True, "removed": removed}


@app.post("/api/workbench/reset")
def reset_workspace():
    with core.db() as conn:
        ids = [x["id"] for x in conn.execute("SELECT id FROM artifacts").fetchall()]
        removed = delete_artifacts(conn, ids)
        conn.execute("DELETE FROM tool_runs")
        conn.execute("DELETE FROM events")
        conn.commit()
    return {"ok": True, "removed": removed}


@app.get("/")
def workbench_index():
    return FileResponse(core.ROOT / "frontend" / "workbench.html")


# Keep all existing v0.1 API routes and downloads working. The legacy app is
# mounted last so the workbench routes above take precedence.
app.mount("/", core.app)
