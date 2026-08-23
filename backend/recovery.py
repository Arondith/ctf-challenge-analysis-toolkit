from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

from backend import main as core
from backend import workbench as wb


def canonical_artifact_path(row) -> Path:
    return core.WORKSPACE / "artifacts" / row["id"] / row["filename"]


def repair_or_prune_stale_artifacts() -> int:
    """Repair moved artifact paths and remove DB trees whose bytes are gone."""
    with core.db() as conn:
        rows = conn.execute("SELECT * FROM artifacts").fetchall()
        missing = set()

        for row in rows:
            stored = Path(row["path"])
            if stored.is_file():
                continue

            canonical = canonical_artifact_path(row)
            if canonical.is_file():
                conn.execute(
                    "UPDATE artifacts SET path=? WHERE id=?",
                    (str(canonical), row["id"]),
                )
            else:
                missing.add(row["id"])

        # If a parent artifact is gone, all descendants belong to that broken
        # analysis tree and should be removed too rather than left orphaned.
        expanded = set(missing)
        changed = True
        while changed:
            changed = False
            for edge in conn.execute("SELECT parent_id, child_id FROM edges").fetchall():
                if edge["parent_id"] in expanded and edge["child_id"] not in expanded:
                    expanded.add(edge["child_id"])
                    changed = True

        removed = wb.delete_artifacts(conn, sorted(expanded)) if expanded else 0
        conn.commit()
        return removed


# Run once when the container starts. This specifically handles persistent
# workspace databases from older/native runs whose absolute paths are invalid
# in the current Docker container.
repair_or_prune_stale_artifacts()


app = FastAPI(
    title="H4G CTF Analysis Workbench",
    version="0.2.1",
    description="Integrated local/authorized CTF artifact analysis workbench with workspace recovery.",
)


@app.get("/api/recovery/health")
def recovery_health():
    return {
        "status": "ok",
        "workspace": str(core.WORKSPACE),
        "mode": "integrated-workbench-recovery",
    }


@app.post("/api/upload")
async def robust_upload(file: UploadFile = File(...)):
    data = bytearray()

    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > core.MAX_UPLOAD:
            raise HTTPException(413, "Upload exceeds configured limit.")

    if not data:
        raise HTTPException(400, "Empty file.")

    payload = bytes(data)
    digest = core.sha256_bytes(payload)

    with core.db() as conn:
        # Demo data is never allowed to contaminate a real challenge upload.
        demo_ids = wb.recursive_demo_ids(conn)
        if demo_ids:
            wb.delete_artifacts(conn, demo_ids)

        existing = conn.execute(
            "SELECT * FROM artifacts WHERE sha256=? LIMIT 1",
            (digest,),
        ).fetchone()

        if existing:
            stored = Path(existing["path"])
            canonical = canonical_artifact_path(existing)

            if not stored.is_file() and canonical.is_file():
                conn.execute(
                    "UPDATE artifacts SET path=? WHERE id=?",
                    (str(canonical), existing["id"]),
                )
                existing = conn.execute(
                    "SELECT * FROM artifacts WHERE id=?",
                    (existing["id"],),
                ).fetchone()

            if Path(existing["path"]).is_file():
                conn.commit()
                result = core.artifact_json(conn, existing)
            else:
                # The same bytes are registered, but their backing file has
                # vanished. Remove that stale analysis tree and rebuild it.
                stale = {existing["id"]}
                changed = True
                while changed:
                    changed = False
                    for edge in conn.execute("SELECT parent_id, child_id FROM edges").fetchall():
                        if edge["parent_id"] in stale and edge["child_id"] not in stale:
                            stale.add(edge["child_id"])
                            changed = True

                wb.delete_artifacts(conn, sorted(stale))
                pipeline = core.Pipeline(conn)
                artifact_id = pipeline.process(
                    payload,
                    file.filename or "artifact.bin",
                    origin="upload",
                    technique="Uploaded artifact",
                )
                conn.commit()
                row = conn.execute(
                    "SELECT * FROM artifacts WHERE id=?",
                    (artifact_id,),
                ).fetchone()
                result = core.artifact_json(conn, row)
        else:
            pipeline = core.Pipeline(conn)
            artifact_id = pipeline.process(
                payload,
                file.filename or "artifact.bin",
                origin="upload",
                technique="Uploaded artifact",
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM artifacts WHERE id=?",
                (artifact_id,),
            ).fetchone()
            result = core.artifact_json(conn, row)

    await core.hub.broadcast(
        {
            "event": "analysis-complete",
            "artifact_id": result["id"],
        }
    )
    return result


# Mount the integrated workbench last. Routes declared above override its
# legacy /api/upload while every other workbench/core route remains available.
app.mount("/", wb.app)
