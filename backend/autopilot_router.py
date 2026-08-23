from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend import main as core
from backend import solve_assistant as reasoning
from backend import solver_prompt_patch as prompt_patch
from backend.autopilot_engine import (
    accept_reasoning_candidate,
    case_snapshot,
    create_or_resume_case,
    run_case_tick,
)
from backend.challenge_context import infer_challenge_context

router = APIRouter()


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


async def _reason_about_case(snapshot: dict, mode: str) -> dict:
    root_id, evidence = reasoning.collect_evidence(snapshot["root_artifact_id"])
    timeline = "\n".join(
        f"- {item['message']}" for item in snapshot.get("timeline", [])[-20:]
    )
    evidence = (
        f"CTF AUTOPILOT CASE STATE\n"
        f"State: {snapshot['state']}\n"
        f"Stage: {snapshot['stage_name']}\n"
        f"Current plan: {snapshot['current_plan']}\n"
        f"Artifacts: {snapshot['artifact_count']}\n"
        f"Strategy resets: {snapshot['strategy_resets']}\n\n"
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
    snapshot = await run_case_tick(case_id)
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
        "enhanced_reasoning": bool(reasoning.OPENAI_API_KEY),
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
        return case_snapshot(case_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
