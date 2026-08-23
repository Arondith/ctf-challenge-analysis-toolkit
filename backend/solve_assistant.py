from __future__ import annotations

import json
import os
import re
from typing import Literal

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend import main as core

router = APIRouter()
AI_MODEL = os.getenv("H4G_AI_MODEL", "gpt-5.6")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
MAX_EVIDENCE_CHARS = int(os.getenv("H4G_SOLVER_MAX_EVIDENCE", "30000"))


def ensure_solver_db() -> None:
    with core.db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS solve_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_artifact_id TEXT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                mode TEXT NOT NULL,
                candidate TEXT,
                confidence REAL NOT NULL,
                explanation TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


ensure_solver_db()


class SolveRequest(BaseModel):
    title: str = Field(default="", max_length=240)
    description: str = Field(default="", max_length=12000)
    root_artifact_id: str | None = Field(default=None, max_length=64)
    candidate_flag: str | None = Field(default=None, max_length=260)
    mode: Literal["local", "ai", "auto"] = "auto"


def _root_id(conn, requested: str | None) -> str | None:
    if requested:
        row = conn.execute("SELECT id FROM artifacts WHERE id=?", (requested,)).fetchone()
        if not row:
            raise HTTPException(404, "Root artifact not found.")
        return requested
    row = conn.execute(
        "SELECT id FROM artifacts WHERE origin!='demo' AND parent_id IS NULL ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    return row["id"] if row else None


def _tree_ids(conn, root_id: str | None) -> list[str]:
    if not root_id:
        return []
    rows = conn.execute(
        """
        WITH RECURSIVE tree(id) AS (
            SELECT ?
            UNION
            SELECT e.child_id FROM edges e JOIN tree t ON e.parent_id=t.id
        )
        SELECT id FROM tree LIMIT 250
        """,
        (root_id,),
    ).fetchall()
    return [r["id"] for r in rows]


def collect_evidence(root_artifact_id: str | None) -> tuple[str | None, str]:
    with core.db() as conn:
        root_id = _root_id(conn, root_artifact_id)
        ids = _tree_ids(conn, root_id)
        if not ids:
            return root_id, "No imported artifact evidence is currently available."
        marks = ",".join("?" for _ in ids)
        artifacts = conn.execute(
            f"SELECT id, filename, kind, mime, size, entropy, origin, technique FROM artifacts WHERE id IN ({marks}) ORDER BY created_at",
            ids,
        ).fetchall()
        findings = conn.execute(
            f"SELECT artifact_id, category, title, value, confidence FROM findings WHERE artifact_id IN ({marks}) ORDER BY confidence DESC LIMIT 140",
            ids,
        ).fetchall()
        flags = conn.execute(
            f"SELECT artifact_id, flag, confidence, status, technique FROM flags WHERE artifact_id IN ({marks}) ORDER BY confidence DESC LIMIT 100",
            ids,
        ).fetchall()
        tool_runs = []
        try:
            tool_runs = conn.execute(
                f"SELECT artifact_id, label, output, status FROM tool_runs WHERE artifact_id IN ({marks}) ORDER BY id DESC LIMIT 100",
                ids,
            ).fetchall()
        except Exception:
            pass

    parts = ["ARTIFACTS"]
    for r in artifacts:
        parts.append(
            f"- {r['id']} {r['filename']} | {r['kind']}/{r['mime']} | {r['size']} bytes | entropy {r['entropy']:.3f} | {r['technique']}"
        )
    parts.append("\nFINDINGS")
    for r in findings:
        value = (r["value"] or "").replace("\x00", " ")[:700]
        parts.append(f"- {r['artifact_id']} [{r['confidence']:.0%}] {r['title']}: {value}")
    parts.append("\nFLAG CANDIDATES")
    for r in flags:
        flag = r["flag"]
        printable = flag.isascii() and flag.isprintable()
        parts.append(
            f"- {r['artifact_id']} [{r['confidence']:.0%}] {flag!r} | status={r['status']} | printable_ascii={printable} | {r['technique']}"
        )
    parts.append("\nTOOL OUTPUT HIGHLIGHTS")
    interesting = re.compile(
        r"(?i)flag|clue|secret|password|metadata|comment|message|subject|dns|icmp|http|smtp|ftp|nfs|hid|xor|"
        r"spectrogram|stux|duqu|worm|pyinstaller|pyi-|entry point|bytecode|load_const|constant|sonar|ship|grid|ping|"
        r"frequency|\bhz\b|\.wav|restart|sweep|success|coordinate|base64|archive|extract"
    )
    for r in tool_runs:
        output = r["output"] or ""
        lines = [line.strip() for line in output.splitlines() if interesting.search(line)]
        # Disassembly and extraction reports are intrinsically high-value even if
        # a relevant constant does not match one of the keyword filters.
        if not lines and any(x in (r["label"] or "").lower() for x in ("disassembly", "pyinstaller")):
            lines = [line.strip() for line in output.splitlines() if line.strip()][:18]
        if lines:
            parts.append(f"- {r['artifact_id']} {r['label']} ({r['status']}): " + " | ".join(lines[:18])[:2600])
    text = "\n".join(parts)
    return root_id, text[:MAX_EVIDENCE_CHARS]


def format_flag(answer: str, challenge_text: str) -> str:
    answer = answer.strip().strip("{}")
    format_match = re.search(r"(?i)flag\s*format\s*:\s*([A-Za-z0-9_-]+)\{", challenge_text)
    prefix = format_match.group(1) if format_match else "H4G"
    return f"{prefix}{{{answer}}}"


def _is_placeholder_flag(value: str) -> bool:
    match = re.fullmatch(r"[A-Za-z0-9_-]+\{(.*)\}", value.strip())
    if not match:
        return False
    body = match.group(1).strip().lower()
    if body in {"flag", "answer", "example", "actual_flag", "actual answer", "actual_answer", "hash", "tool name"}:
        return True
    if re.fullmatch(r"part\d+(?:_part\d+)+", body):
        return True
    if "coordinateid" in body or body.startswith("id1-"):
        return True
    return False


def _unique_grid_coordinates(evidence: str) -> list[str]:
    seen: set[str] = set()
    coords: list[str] = []
    for value in re.findall(r"\b[A-J](?:10|[1-9])\b", evidence, re.I):
        item = value.upper()
        if item not in seen:
            seen.add(item)
            coords.append(item)
    return coords


def local_reasoning(title: str, description: str, evidence: str, supplied: str | None) -> dict:
    text = f"{title}\n{description}".strip()
    low = text.lower()
    evlow = evidence.lower()
    steps: list[str] = []
    next_actions: list[str] = []
    candidate = supplied.strip() if supplied else ""
    confidence = 0.35

    # Knowledge relation, not a challenge-title lookup: Stuxnet (2010) -> Duqu.
    if "2010" in low and "worm" in low:
        steps.append("The clue 'famous 2010 worm' strongly points to Stuxnet.")
        confidence = max(confidence, 0.72)
        if any(x in low for x in ("came after", "after a famous", "silent strike", "followed")):
            steps.append("A prominent post-Stuxnet malware family closely related to Stuxnet is Duqu, which was oriented toward intelligence gathering rather than Stuxnet-style sabotage.")
            candidate = candidate or format_flag("Duqu", text)
            confidence = max(confidence, 0.90)

    if "not everything is conveyed through sound" in low or ("audio" in low and "hidden" in low):
        steps.append("The wording says the audio may be a carrier or clue rather than something solved by listening alone; signal and metadata evidence matter.")

    if "static" in low or "noise" in low:
        steps.append("Static/noise can be thematic misdirection; the semantic wording of the prompt may carry the decisive clue.")

    if "sonar" in low and ("ship" in low or "grid" in low or "ping" in low):
        steps.append("The challenge describes a sonar/grid problem, so the objective is to recover the complete target layout and continue to the success/flag condition, not merely identify the executable type.")
        confidence = max(confidence, 0.55)
        coords = _unique_grid_coordinates(evidence)
        if len(coords) >= 5:
            steps.append("Grid-like coordinates were recovered from analysis evidence: " + ", ".join(coords[:40]) + ".")
            confidence = max(confidence, 0.68)
        if "extract pyinstaller application" in evlow or "pyinstaller extraction" in evlow:
            steps.append("The executable is a PyInstaller application and its bundled Python code/resources have been extracted for recursive analysis.")
        elif "pyi-python-flag" in evlow or "pyrun_simplestringflags" in evlow:
            next_actions.append("Extract the PyInstaller application and disassemble its entry-point bytecode.")

    if "spaces" in low or "whitespace" in low:
        steps.append("The prompt emphasizes spaces/whitespace, so trailing spaces and tabs are a likely binary/steganographic channel.")

    if re.search(r"\b64\b", text) or "base64" in low:
        steps.append("The explicit '64' clue makes Base64 a high-priority decoding hypothesis.")

    if "single xor" in low and "hid" in low:
        steps.append("The prompt explicitly calls for one XOR layer plus HID usage-table decoding.")

    if "five different protocols" in low or "part1_part2_part3_part4_part5" in low:
        steps.append("The prompt defines a multipart flag distributed across protocols, so the correct task is correlation rather than choosing one raw packet string.")

    if "nfs" in low and ("leak" in low or "recover" in low):
        steps.append("NFS is explicitly identified as the transfer mechanism; reconstructed NFS file data is higher-value evidence than generic packet strings.")

    if "closest" in low and "farthest" in low and "coordinate" in low:
        steps.append("The flag is derived from computed relationships between coordinate IDs, not a literal string in the CSV.")

    if "pyi-python-flag" in evlow or "pyrun_simplestringflags" in evlow:
        steps.append("The PE contains PyInstaller/Python runtime indicators; generic PE strings alone are insufficient, so bundled Python code should be the primary reverse-engineering target.")

    known_flags = re.findall(r"(?:H4G|HACK4GOV|CTF|FLAG)\{[ -~]{3,200}?\}", evidence)
    clean_flags = [
        x for x in known_flags
        if x.isascii() and x.isprintable() and not _is_placeholder_flag(x)
    ]
    if clean_flags:
        steps.append("The analysis evidence contains a clean, non-placeholder known-format flag; it outranks generic regex matches and indirect hypotheses.")
        if not candidate:
            candidate = clean_flags[0]
            confidence = max(confidence, 0.92)

    if candidate and _is_placeholder_flag(candidate):
        candidate = ""

    noisy_count = len(re.findall(r"printable_ascii=False", evidence))
    if noisy_count:
        steps.append(f"{noisy_count} stored candidates contain non-printable/non-ASCII data and are being treated as binary false positives.")

    if not steps:
        steps.append("The automatic analyzers produced evidence, but no deterministic local solver rule can yet justify a final flag.")

    if not candidate:
        if not description.strip():
            next_actions.append("Challenge wording is unavailable; provide it if it is not recoverable from the bundled challenge metadata.")
        if "pyi-python-flag" in evlow and "pyinstaller extraction" not in evlow:
            next_actions.append("Extract and recursively analyze the PyInstaller application.")
        elif "sonar" in low and "ship" in low:
            next_actions.append("Continue from extracted program/audio evidence until the success condition reveals or constructs the flag.")
        elif not next_actions:
            next_actions.append("Use the highest-value unexhausted analyzer supported by the current evidence; do not rerun completed generic triage without a reason.")

    explanation = "\n".join(f"{i+1}. {step}" for i, step in enumerate(steps))
    return {
        "candidate": candidate or None,
        "confidence": round(confidence, 2),
        "reasoning_summary": explanation,
        "next_actions": next_actions[:8],
        "mode": "local",
    }


def extract_response_text(payload: dict) -> str:
    if isinstance(payload.get("output_text"), str):
        return payload["output_text"]
    chunks: list[str] = []
    for item in payload.get("output", []) or []:
        for content in item.get("content", []) or []:
            text = content.get("text")
            if isinstance(text, str):
                chunks.append(text)
    return "\n".join(chunks).strip()


async def ai_reasoning(title: str, description: str, evidence: str, supplied: str | None) -> dict:
    if not OPENAI_API_KEY:
        raise HTTPException(503, "AI mode is not configured. Set OPENAI_API_KEY for the Docker service, or use Local Reasoning.")
    prompt = f"""You are the Solve Assistant inside an authorized local CTF workbench.
Produce a concise analyst-facing reasoning summary, not hidden chain-of-thought.
Do not trust broad regex flag candidates merely because they contain braces. Reject binary/non-printable garbage.
Never treat a stated flag-format placeholder such as H4G{{flag}} or H4G{{Answer}} as a recovered flag.
Distinguish: (1) evidence from the artifact/tool output, (2) clues from the challenge wording, and (3) background cybersecurity/general knowledge.
If the challenge is knowledge/riddle based, solve the clue and format the answer exactly as the stated flag format.
If evidence is insufficient, say so and recommend the next concrete analyzer action.
Do not invent a flag.

Return Markdown with these headings:
## Likely Answer
## Why
## Evidence Used
## False Positives / Uncertainty
## Next Validation

Challenge title: {title or '(not supplied)'}
Challenge prompt:
{description or '(not supplied)'}

User-supplied candidate: {supplied or '(none)'}

Local workbench evidence:
{evidence}
"""
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    body = {"model": AI_MODEL, "input": prompt, "max_output_tokens": 1400}
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post("https://api.openai.com/v1/responses", headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"AI request failed: {exc}") from exc
    if response.status_code >= 400:
        detail = response.text[:1200]
        raise HTTPException(502, f"AI provider returned HTTP {response.status_code}: {detail}")
    payload = response.json()
    text = extract_response_text(payload)
    if not text:
        raise HTTPException(502, "AI provider returned no text output.")
    candidate_match = re.search(r"(?:H4G|HACK4GOV|CTF|FLAG)\{[ -~]{3,200}?\}", text)
    candidate = candidate_match.group(0) if candidate_match else None
    if candidate and _is_placeholder_flag(candidate):
        candidate = None
    return {
        "candidate": candidate,
        "confidence": 0.0,
        "reasoning_summary": text,
        "next_actions": [],
        "mode": "ai",
        "model": AI_MODEL,
    }


def save_session(root_id: str | None, req: SolveRequest, result: dict) -> int:
    with core.db() as conn:
        cur = conn.execute(
            """
            INSERT INTO solve_sessions(root_artifact_id,title,description,mode,candidate,confidence,explanation,created_at)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                root_id,
                req.title,
                req.description,
                result.get("mode", req.mode),
                result.get("candidate"),
                float(result.get("confidence") or 0),
                result.get("reasoning_summary", ""),
                core.now(),
            ),
        )
        return int(cur.lastrowid)


@router.get("/solve-assistant")
def solve_assistant_page():
    return FileResponse(core.ROOT / "frontend" / "solve_assistant.html")


@router.get("/api/h4g/solve/status")
def solve_status():
    return {
        "local_available": True,
        "ai_available": bool(OPENAI_API_KEY),
        "ai_model": AI_MODEL if OPENAI_API_KEY else None,
        "privacy_note": "AI mode sends the challenge prompt and a bounded evidence summary to the configured OpenAI API. Local mode stays inside the workbench.",
    }


@router.get("/api/h4g/solve/recent")
def recent_solves():
    with core.db() as conn:
        rows = conn.execute(
            "SELECT id,root_artifact_id,title,mode,candidate,confidence,explanation,created_at FROM solve_sessions ORDER BY id DESC LIMIT 12"
        ).fetchall()
    return [dict(r) for r in rows]


@router.post("/api/h4g/solve")
async def solve(req: SolveRequest):
    root_id, evidence = collect_evidence(req.root_artifact_id)
    local = local_reasoning(req.title, req.description, evidence, req.candidate_flag)
    if req.mode == "local":
        result = local
    elif req.mode == "ai":
        result = await ai_reasoning(req.title, req.description, evidence, req.candidate_flag)
        result["local_hint"] = local
    else:
        if OPENAI_API_KEY:
            try:
                result = await ai_reasoning(req.title, req.description, evidence, req.candidate_flag)
                result["local_hint"] = local
            except HTTPException:
                result = local
        else:
            result = local
    result["root_artifact_id"] = root_id
    result["evidence_preview"] = evidence[:4000]
    result["session_id"] = save_session(root_id, req, result)
    return result
