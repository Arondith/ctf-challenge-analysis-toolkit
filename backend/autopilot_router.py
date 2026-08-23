from __future__ import annotations

import json
import os

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend import main as core
from backend import solve_assistant as reasoning
from backend import solver_prompt_patch as prompt_patch
# Imported for side effects after the deep binary/audio registry has been installed
# by the runtime. This adds Python/internal fallback analyzers to the same safe
# allow-listed catalog consumed by the Case Director.
from backend import fallback_analyzers as fallback_analyzers  # noqa: F401
from backend.autopilot_engine import (
    accept_reasoning_candidate,
    case_snapshot,
    create_or_resume_case,
    run_case_tick,
)
from backend.autopilot_state import refresh_case_reasoning_state
from backend.challenge_context import infer_challenge_context

router = APIRouter()
MAX_BUNDLE_BYTES = int(os.getenv("CTF_AUTOPILOT_BUNDLE_MAX", str(512 * 1024 * 1024)))
MAX_BUNDLE_FILES = int(os.getenv("CTF_AUTOPILOT_BUNDLE_FILES", "500"))


class StartRequest(BaseModel):
    root_artifact_id: str | None = Field(default=None, max_length=64)
    title: str = Field(default="", max_length=240)
    description: str = Field(default="", max_length=12000)
    mode: str = Field(default="auto", pattern=r"^(auto|local|ai)$")


class ContinueRequest(BaseModel):
    mode: str = Field(default="auto", pattern=r"^(auto|local|ai)$")


def _resolve_root(requested: str | None) -> str:
    with core.db() as conn:
        root = reasoning._root_id(conn, requested)
    if not root:
        raise HTTPException(404, "No uploaded challenge artifact is available.")
    return root


async def _read_upload(upload: UploadFile) -> bytes:
    data = bytearray()
    while True:
        chunk = await upload.read(1024 * 1024)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > core.MAX_UPLOAD:
            raise HTTPException(413, f"{upload.filename or 'file'} exceeds the per-file upload limit.")
    if not data:
        raise HTTPException(400, f"{upload.filename or 'file'} is empty.")
    return bytes(data)


async def _load_files(files: list[UploadFile]) -> tuple[list[tuple[str, bytes]], int]:
    if not files:
        raise HTTPException(400, "No challenge files supplied.")
    if len(files) > MAX_BUNDLE_FILES:
        raise HTTPException(413, f"Challenge bundle exceeds {MAX_BUNDLE_FILES} files.")
    loaded: list[tuple[str, bytes]] = []
    total = 0
    for upload in files:
        data = await _read_upload(upload)
        total += len(data)
        if total > MAX_BUNDLE_BYTES:
            raise HTTPException(413, "Challenge bundle exceeds the configured total upload limit.")
        loaded.append((upload.filename or "artifact.bin", data))
    return loaded, total


async def _reason_about_case(snapshot: dict, mode: str) -> dict:
    _, evidence = reasoning.collect_evidence(snapshot["root_artifact_id"])
    timeline = "\n".join(
        f"- {item['message']}" for item in snapshot.get("timeline", [])[-20:]
    )
    target = snapshot.get("solve_target") or {}
    hypotheses = snapshot.get("hypotheses") or []
    hypothesis_text = "\n".join(
        f"- {item['statement']} ({float(item['confidence']):.0%})"
        for item in hypotheses[:8]
    )
    evidence = (
        f"CTF AUTOPILOT CASE STATE\n"
        f"State: {snapshot['state']}\n"
        f"Stage: {snapshot['stage_name']}\n"
        f"Current plan: {snapshot['current_plan']}\n"
        f"Solve target: {target.get('answer_type', 'unknown')}\n"
        f"Target completion: {json.dumps(target.get('completion', {}), sort_keys=True)}\n"
        f"Artifacts: {snapshot['artifact_count']}\n"
        f"Strategy resets: {snapshot['strategy_resets']}\n\n"
        f"ACTIVE HYPOTHESES\n{hypothesis_text or '- none yet'}\n\n"
        f"RECENT INVESTIGATION TIMELINE\n{timeline}\n\n"
        + evidence
    )

    local = reasoning.local_reasoning(
        snapshot.get("title", ""),
        snapshot.get("description", ""),
        evidence,
        None,
    )

    if mode == "local":
        return local
    if mode == "ai":
        return await prompt_patch.solve_first_reasoning(
            snapshot.get("title", ""),
            snapshot.get("description", ""),
            evidence,
            None,
        )
    if reasoning.OPENAI_API_KEY:
        try:
            return await prompt_patch.solve_first_reasoning(
                snapshot.get("title", ""),
                snapshot.get("description", ""),
                evidence,
                None,
            )
        except Exception:
            return local
    return local


async def _advance(case_id: int, mode: str) -> dict:
    pre_state = refresh_case_reasoning_state(case_id)
    snapshot = await run_case_tick(case_id)
    post_state = refresh_case_reasoning_state(case_id)
    snapshot.update(post_state)
    reasoned = None

    # Correlation/riddle reasoning is another solver capability, not a user-facing
    # recommendation. It runs automatically after each analyzer batch.
    if snapshot["state"] != "SOLVED":
        try:
            reasoned = await _reason_about_case(snapshot, mode)
        except Exception as exc:
            reasoned = {
                "candidate": None,
                "confidence": 0.0,
                "reasoning_summary": f"Reasoning pass unavailable: {type(exc).__name__}",
                "mode": "local",
            }

        candidate = reasoned.get("candidate") if reasoned else None
        confidence = float(reasoned.get("confidence") or 0) if reasoned else 0.0
        if accept_reasoning_candidate(
            case_id,
            candidate,
            confidence,
            reasoned.get("reasoning_summary", "") if reasoned else "",
        ):
            snapshot = case_snapshot(case_id)
            snapshot.update(refresh_case_reasoning_state(case_id))

    snapshot["reasoning"] = reasoned
    return snapshot


@router.get("/autopilot")
def autopilot_page():
    return FileResponse(core.ROOT / "frontend" / "autopilot.html")


@router.get("/api/autopilot/status")
def autopilot_status():
    return {
        "name": "CTF AUTOPILOT",
        "tagline": "DROP THE CHALLENGE. GET THE FLAG.",
        "persistent_cases": True,
        "fallback_engine": True,
        "strategy_reset": True,
        "anti_loop_memory": True,
        "internal_fallback_parsers": True,
        "multi_file_cases": True,
        "resumable_cases": True,
        "solve_target_tracking": True,
        "competing_hypotheses": True,
        "enhanced_reasoning": bool(reasoning.OPENAI_API_KEY),
    }


@router.post("/api/autopilot/upload")
async def upload_bundle(files: list[UploadFile] = File(...)):
    loaded, total = await _load_files(files)

    with core.db() as conn:
        pipeline = core.Pipeline(conn)
        if len(loaded) == 1:
            name, data = loaded[0]
            root_id = pipeline.process(data, core.safe_filename(name), origin="upload", technique="CTF Autopilot upload")
            imported = [root_id]
        else:
            manifest = {
                "case_type": "CTF Autopilot multi-file challenge",
                "file_count": len(loaded),
                "total_bytes": total,
                "files": [{"name": name, "size": len(data)} for name, data in loaded],
            }
            root_id = pipeline.process(
                json.dumps(manifest, indent=2).encode("utf-8"),
                "autopilot_case_manifest.json",
                origin="upload",
                technique="CTF Autopilot challenge bundle",
            )
            imported = [root_id]
            for name, data in loaded:
                child = pipeline.process(
                    data,
                    core.safe_filename(name),
                    parent=root_id,
                    origin="upload",
                    technique=f"Challenge bundle member: {name}",
                    depth=1,
                )
                imported.append(child)
        conn.commit()

    await core.hub.broadcast({"event": "autopilot-upload", "artifact_id": root_id})
    return {
        "root_artifact_id": root_id,
        "artifacts": imported,
        "files": len(loaded),
        "total_bytes": total,
    }


@router.post("/api/autopilot/cases/{case_id}/evidence")
async def add_case_evidence(case_id: int, files: list[UploadFile] = File(...)):
    loaded, total = await _load_files(files)
    with core.db() as conn:
        case = conn.execute("SELECT * FROM autopilot_cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            raise HTTPException(404, "Autopilot case not found.")
        pipeline = core.Pipeline(conn)
        imported = []
        for name, data in loaded:
            child = pipeline.process(
                data,
                core.safe_filename(name),
                parent=case["root_artifact_id"],
                origin="upload",
                technique=f"Additional case evidence: {name}",
                depth=1,
            )
            imported.append(child)
        conn.execute(
            """
            UPDATE autopilot_cases
            SET state='INVESTIGATING',blocker=NULL,stagnation=0,updated_at=?
            WHERE id=?
            """,
            (core.now(), case_id),
        )
        conn.execute(
            "INSERT INTO autopilot_timeline(case_id,level,message,created_at) VALUES(?,?,?,?)",
            (case_id, "adapt", f"New evidence added ({len(imported)} file(s)); reopening the persistent investigation.", core.now()),
        )
        conn.commit()

    await core.hub.broadcast({"event": "autopilot-new-evidence", "artifact_id": case["root_artifact_id"]})
    result = case_snapshot(case_id)
    result.update(refresh_case_reasoning_state(case_id))
    return {
        "case": result,
        "artifacts": imported,
        "files": len(loaded),
        "total_bytes": total,
    }


@router.post("/api/autopilot/start")
async def start(req: StartRequest):
    root_id = _resolve_root(req.root_artifact_id)
    title, description, context_source = infer_challenge_context(
        root_id,
        req.title,
        req.description,
    )
    case_id = create_or_resume_case(root_id, title, description)
    result = await _advance(case_id, req.mode)
    result["context_source"] = context_source
    return result


@router.post("/api/autopilot/cases/{case_id}/continue")
async def continue_case(case_id: int, req: ContinueRequest):
    try:
        return await _advance(case_id, req.mode)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/api/autopilot/cases/{case_id}")
def get_case(case_id: int):
    try:
        result = case_snapshot(case_id)
        result.update(refresh_case_reasoning_state(case_id))
        return result
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
