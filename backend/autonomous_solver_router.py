from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from backend import main as core
from backend import solve_assistant as base
from backend import solver_prompt_patch as prompt_patch
from backend.autonomous_runner import run_autonomous_analysis


router = APIRouter()


@router.get("/solve-assistant")
def solve_assistant_page():
    return FileResponse(core.ROOT / "frontend" / "solve_assistant.html")


@router.get("/api/h4g/solve/status")
def solve_status():
    return {
        "local_available": True,
        "ai_available": bool(base.OPENAI_API_KEY),
        "ai_model": base.AI_MODEL if base.OPENAI_API_KEY else None,
        "privacy_note": (
            "Local analysis runs inside the workbench. Enhanced reasoning sends only the "
            "challenge prompt and a bounded evidence summary to the configured reasoning service."
        ),
        "autonomous_analysis": True,
    }


@router.get("/api/h4g/solve/recent")
def recent_solves():
    with core.db() as conn:
        rows = conn.execute(
            "SELECT id,root_artifact_id,title,mode,candidate,confidence,explanation,created_at "
            "FROM solve_sessions ORDER BY id DESC LIMIT 12"
        ).fetchall()
    return [dict(row) for row in rows]


def resolve_root(requested: str | None) -> str | None:
    with core.db() as conn:
        return base._root_id(conn, requested)


@router.post("/api/h4g/solve")
async def solve(req: base.SolveRequest):
    root_id = resolve_root(req.root_artifact_id)
    auto_report = None

    # Execution authority: before reasoning, run every registered allow-listed
    # automatic analyzer across the root artifact tree. Newly produced children
    # are picked up on later passes by autonomous_runner.
    if root_id:
        auto_report = await run_autonomous_analysis(root_id)

    root_id, evidence = base.collect_evidence(root_id)
    if auto_report:
        evidence += (
            "\n\nAUTONOMOUS ANALYSIS SUMMARY\n"
            f"- actions: {auto_report['actions']}\n"
            f"- artifacts_seen: {auto_report['artifacts_seen']}\n"
            f"- passes: {auto_report['passes']}\n"
            f"- stopped_reason: {auto_report['stopped_reason']}"
        )

    local = base.local_reasoning(
        req.title,
        req.description,
        evidence,
        req.candidate_flag,
    )

    if req.mode == "local":
        result = local
    elif req.mode == "ai":
        result = await prompt_patch.solve_first_reasoning(
            req.title,
            req.description,
            evidence,
            req.candidate_flag,
        )
        result["local_hint"] = local
    else:
        if base.OPENAI_API_KEY:
            try:
                result = await prompt_patch.solve_first_reasoning(
                    req.title,
                    req.description,
                    evidence,
                    req.candidate_flag,
                )
                result["local_hint"] = local
            except HTTPException:
                result = local
        else:
            result = local

    result["root_artifact_id"] = root_id
    result["evidence_preview"] = evidence[:4000]
    result["autonomous_analysis"] = auto_report
    result["session_id"] = base.save_session(root_id, req, result)
    return result
