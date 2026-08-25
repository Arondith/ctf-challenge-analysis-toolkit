from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from typing import Any

from backend import main as core
from backend import workbench as wb

ENGINE_VERSION = "1"
MAX_ACTIONS_PER_TICK = int(os.getenv("CTF_AUTOPILOT_ACTIONS_PER_TICK", "80"))
MAX_TREE_ARTIFACTS = int(os.getenv("CTF_AUTOPILOT_MAX_ARTIFACTS", "300"))
STAGNATION_THRESHOLD = int(os.getenv("CTF_AUTOPILOT_STAGNATION", "6"))
MAX_STAGE = 7

STAGE_NAMES = {
    1: "FAST_TRIAGE",
    2: "TYPE_SPECIFIC",
    3: "TARGETED_DEEP",
    4: "FALLBACK_METHODS",
    5: "STRATEGY_RESET",
    6: "RAW_STRUCTURAL",
    7: "FINAL_DEEP_PASS",
}

PLACEHOLDER_BODIES = {
    "flag", "answer", "example", "here", "actual_flag", "your_flag",
    "placeholder", "insert_flag", "the_flag", "sample", "test",
}


def ensure_autopilot_db() -> None:
    with core.db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS autopilot_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_artifact_id TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'CASE_CREATED',
                stage INTEGER NOT NULL DEFAULT 1,
                stagnation INTEGER NOT NULL DEFAULT 0,
                strategy_resets INTEGER NOT NULL DEFAULT 0,
                flag TEXT,
                confidence REAL NOT NULL DEFAULT 0,
                blocker TEXT,
                context_version TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS autopilot_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                artifact_id TEXT NOT NULL,
                analysis_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                label TEXT NOT NULL,
                state TEXT NOT NULL,
                failure_type TEXT,
                summary TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(case_id, signature)
            );

            CREATE INDEX IF NOT EXISTS idx_autopilot_actions_case
            ON autopilot_actions(case_id, id DESC);

            CREATE TABLE IF NOT EXISTS autopilot_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_autopilot_timeline_case
            ON autopilot_timeline(case_id, id DESC);

            CREATE TABLE IF NOT EXISTS autopilot_dead_ends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                artifact_id TEXT,
                analysis_id TEXT,
                reason TEXT NOT NULL,
                revisit_if TEXT,
                created_at TEXT NOT NULL
            );
            """
        )


ensure_autopilot_db()


def _context_version(title: str, description: str) -> str:
    data = (title.strip() + "\n" + description.strip()).encode("utf-8", errors="ignore")
    return hashlib.sha256(data).hexdigest()[:16]


def _timeline(conn, case_id: int, message: str, level: str = "info") -> None:
    conn.execute(
        "INSERT INTO autopilot_timeline(case_id,level,message,created_at) VALUES(?,?,?,?)",
        (case_id, level, message[:2000], core.now()),
    )


def create_or_resume_case(root_artifact_id: str, title: str, description: str) -> int:
    version = _context_version(title, description)
    with core.db() as conn:
        exists = conn.execute("SELECT id FROM artifacts WHERE id=?", (root_artifact_id,)).fetchone()
        if not exists:
            raise ValueError("Root artifact not found")

        row = conn.execute(
            "SELECT * FROM autopilot_cases WHERE root_artifact_id=?",
            (root_artifact_id,),
        ).fetchone()
        if row:
            changed = row["context_version"] != version
            state = row["state"]
            if state == "SUSPENDED_EXTERNAL_BLOCKER" and changed:
                state = "INVESTIGATING"
            conn.execute(
                """
                UPDATE autopilot_cases
                SET title=?,description=?,context_version=?,state=?,updated_at=?
                WHERE id=?
                """,
                (title, description, version, state, core.now(), row["id"]),
            )
            if changed:
                _timeline(conn, row["id"], "New challenge context received; reconsidering suspended and low-value paths.", "adapt")
            return int(row["id"])

        cur = conn.execute(
            """
            INSERT INTO autopilot_cases(
                root_artifact_id,title,description,state,stage,stagnation,
                strategy_resets,confidence,context_version,created_at,updated_at
            ) VALUES(?,?,?,'UNDERSTANDING',1,0,0,0,?,?,?)
            """,
            (root_artifact_id, title, description, version, core.now(), core.now()),
        )
        case_id = int(cur.lastrowid)
        _timeline(conn, case_id, "Challenge received. CTF AUTOPILOT started persistent investigation.", "start")
        return case_id


def _case(conn, case_id: int):
    row = conn.execute("SELECT * FROM autopilot_cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        raise ValueError("Autopilot case not found")
    return row


def _tree_rows(conn, root_id: str) -> list[Any]:
    rows = conn.execute(
        """
        WITH RECURSIVE tree(id) AS (
            SELECT ?
            UNION
            SELECT e.child_id FROM edges e JOIN tree t ON e.parent_id=t.id
        )
        SELECT a.* FROM artifacts a JOIN tree t ON a.id=t.id
        ORDER BY a.created_at
        LIMIT ?
        """,
        (root_id, MAX_TREE_ARTIFACTS),
    ).fetchall()
    return list(rows)


def _tool_run(conn, artifact_id: str, analysis_id: str):
    return conn.execute(
        """
        SELECT id,status,returncode,output FROM tool_runs
        WHERE artifact_id=? AND analysis_id=?
        ORDER BY id DESC LIMIT 1
        """,
        (artifact_id, analysis_id),
    ).fetchone()


def _action_signature(case, row, analysis_id: str, spec: dict) -> str:
    tool = spec.get("tool") or "internal"
    payload = {
        "engine": ENGINE_VERSION,
        "artifact": row["id"],
        "analysis": analysis_id,
        "size": row["size"],
        "context": case["context_version"],
        "tool": tool,
        "available": bool(shutil.which(tool)) if tool != "internal" else True,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _record_action(
    conn,
    case_id: int,
    row,
    analysis_id: str,
    signature: str,
    label: str,
    state: str,
    failure_type: str | None,
    summary: str,
    result: dict | None = None,
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO autopilot_actions(
            case_id,artifact_id,analysis_id,signature,label,state,
            failure_type,summary,result_json,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?)
        """,
        (
            case_id,
            row["id"],
            analysis_id,
            signature,
            label,
            state,
            failure_type,
            summary[:3000],
            json.dumps(result or {}, default=str)[:16000],
            core.now(),
        ),
    )


def _already_seen(conn, case_id: int, signature: str) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM autopilot_actions WHERE case_id=? AND signature=?",
        (case_id, signature),
    ).fetchone())


def _classify_failure(result: dict) -> str | None:
    status = str(result.get("status") or "").lower()
    output = str(result.get("output") or "").lower()
    rc = result.get("returncode")

    if status == "missing" or "not installed" in output:
        return "MISSING_DEPENDENCY"
    if status == "timeout" or rc == 124 or "timeout" in output:
        return "TIMEOUT"
    if status == "error" or (isinstance(rc, int) and rc not in {0, 1}):
        return "TOOL_ERROR"
    if any(x in output for x in ("invalid header", "bad magic", "cannot parse", "parse error")):
        return "BAD_PARSE"
    if any(x in output for x in ("corrupt", "truncated", "bad central directory")):
        return "CORRUPTED_INPUT"
    if status in {"complete", "success"} and not result.get("flags") and not result.get("artifacts") and not output.strip():
        return "EMPTY_RESULT"
    return None


def _is_placeholder(flag: str) -> bool:
    m = re.fullmatch(r"[A-Za-z0-9_-]{2,30}\{([^{}]{1,200})\}", flag.strip())
    if not m:
        return True
    body = m.group(1).strip().lower().replace(" ", "_")
    if body in PLACEHOLDER_BODIES:
        return True
    if body.startswith("example") or body.startswith("sample"):
        return True
    return False


def _expected_prefix(description: str) -> str | None:
    m = re.search(r"(?i)flag\s*format\s*:\s*([A-Za-z0-9_-]+)\{", description or "")
    return m.group(1) if m else None


def _verified_flag(conn, case) -> tuple[str | None, float, str | None]:
    rows = _tree_rows(conn, case["root_artifact_id"])
    ids = [r["id"] for r in rows]
    if not ids:
        return None, 0.0, None
    marks = ",".join("?" for _ in ids)
    candidates = conn.execute(
        f"""
        SELECT flag,confidence,status,technique,source,artifact_id
        FROM flags
        WHERE artifact_id IN ({marks}) AND status!='false-positive'
        ORDER BY CASE WHEN status='confirmed' THEN 1 ELSE 0 END DESC, confidence DESC
        """,
        ids,
    ).fetchall()
    expected = _expected_prefix(case["description"])
    for item in candidates:
        flag = (item["flag"] or "").strip()
        if _is_placeholder(flag):
            continue
        if expected and not flag.startswith(expected + "{"):
            continue
        confidence = float(item["confidence"] or 0)
        if item["status"] == "confirmed":
            confidence = max(confidence, 1.0)
        if confidence >= 0.95:
            return flag, confidence, item["technique"]
    return None, 0.0, None


def _family_bonus(kind: str, analysis_id: str, text: str) -> float:
    aid = analysis_id.lower()
    bonus = 0.0
    groups = {
        "pcap": ("pcap.", "network."),
        "pcapng": ("pcap.", "network."),
        "wav": ("audio.", "stego."),
        "pe": ("binary.", "python."),
        "elf": ("binary.",),
        "png": ("image.", "stego."),
        "jpeg": ("image.", "stego."),
        "gif": ("image.",),
        "zip": ("archive.", "deep."),
        "pdf": ("pdf.", "document."),
        "docx": ("archive.", "document."),
        "xlsx": ("archive.", "document."),
        "pptx": ("archive.", "document."),
    }
    if any(aid.startswith(prefix) for prefix in groups.get(kind, ())):
        bonus += 35

    clue_map = {
        "dns": ("dns",),
        "icmp": ("icmp", "ping"),
        "nfs": ("nfs",),
        "hid": ("hid", "keyboard", "keylogger"),
        "xor": ("xor",),
        "audio": ("audio", "sound", "sonar", "ping", "frequency"),
        "image": ("image", "visual", "picture", "qr"),
        "archive": ("zip", "archive", "unzip"),
        "binary": ("exe", "binary", "reverse", "program"),
    }
    low = text.lower()
    for token, clues in clue_map.items():
        if token in aid and any(c in low for c in clues):
            bonus += 20
    return bonus


def _action_score(case, row, analysis_id: str, spec: dict) -> float:
    score = 50.0
    if spec.get("auto"):
        score += 25
    score += _family_bonus(row["kind"], analysis_id, case["title"] + "\n" + case["description"])
    if analysis_id.startswith("deep.") or "carv" in analysis_id:
        score -= 15
    if analysis_id.startswith("file."):
        score += 8 if case["stage"] <= 2 else -5
    if case["stage"] >= 4 and not spec.get("auto"):
        score += 20
    return score


def _eligible(case, spec: dict) -> bool:
    stage = int(case["stage"])
    if stage <= 2:
        return bool(spec.get("auto"))
    if stage == 3:
        return bool(spec.get("auto")) or str(spec.get("special") or "").startswith(("h4g", "deep"))
    return True


def _available_actions(conn, case) -> tuple[list[tuple[float, Any, str, dict, str]], int]:
    actions: list[tuple[float, Any, str, dict, str]] = []
    reused = 0
    for row in _tree_rows(conn, case["root_artifact_id"]):
        try:
            catalog = wb.analysis_catalog(row)
        except Exception:
            continue
        for analysis_id, spec in catalog.items():
            if not _eligible(case, spec):
                continue
            signature = _action_signature(case, row, analysis_id, spec)
            if _already_seen(conn, case["id"], signature):
                continue

            old = _tool_run(conn, row["id"], analysis_id)
            if old and old["status"] == "complete":
                _record_action(
                    conn, case["id"], row, analysis_id, signature,
                    spec.get("label", analysis_id), "REUSED", None,
                    "Existing completed analyzer evidence reused.",
                    {"tool_run_id": old["id"], "status": old["status"]},
                )
                reused += 1
                continue

            actions.append((_action_score(case, row, analysis_id, spec), row, analysis_id, spec, signature))
    actions.sort(key=lambda x: x[0], reverse=True)
    return actions, reused


def _counts(conn, root_id: str) -> tuple[int, int]:
    rows = _tree_rows(conn, root_id)
    ids = [r["id"] for r in rows]
    if not ids:
        return 0, 0
    marks = ",".join("?" for _ in ids)
    flags = conn.execute(
        f"SELECT COUNT(*) AS n FROM flags WHERE artifact_id IN ({marks}) AND status!='false-positive'",
        ids,
    ).fetchone()["n"]
    return len(ids), int(flags)


def _strategy_reset(conn, case, reason: str) -> None:
    stage = min(MAX_STAGE, int(case["stage"]) + 1)
    resets = int(case["strategy_resets"]) + 1
    conn.execute(
        """
        UPDATE autopilot_cases
        SET state='STRATEGY_RESET',stage=?,stagnation=0,strategy_resets=?,updated_at=?
        WHERE id=?
        """,
        (stage, resets, core.now(), case["id"]),
    )
    _timeline(
        conn,
        case["id"],
        f"Strategy reset #{resets}: {reason}. Escalating to {STAGE_NAMES[stage]} and generating a different plan.",
        "adapt",
    )


def _suspend(conn, case, reason: str) -> None:
    conn.execute(
        """
        UPDATE autopilot_cases
        SET state='SUSPENDED_EXTERNAL_BLOCKER',blocker=?,updated_at=?
        WHERE id=?
        """,
        (reason[:2000], core.now(), case["id"]),
    )
    _timeline(conn, case["id"], "All registered internal paths and final deep-pass actions are exhausted. Case suspended, not failed.", "blocked")


def _summary(result: dict) -> str:
    label = result.get("label") or result.get("analysis_id") or "analyzer"
    flags = result.get("flags") or []
    artifacts = result.get("artifacts") or []
    if flags:
        return f"{label}: produced {len(flags)} candidate flag(s)."
    if artifacts:
        return f"{label}: produced {len(artifacts)} derived artifact(s); following them automatically."
    output = str(result.get("output") or "").strip().replace("\x00", " ")
    return f"{label}: {output[:240]}" if output else f"{label}: completed."


async def run_case_tick(case_id: int) -> dict:
    executed = 0
    reused_total = 0

    with core.db() as conn:
        case = _case(conn, case_id)
        if case["state"] in {"SOLVED", "SUSPENDED_EXTERNAL_BLOCKER"}:
            return case_snapshot(case_id)

        conn.execute(
            "UPDATE autopilot_cases SET state='INVESTIGATING',updated_at=? WHERE id=?",
            (core.now(), case_id),
        )
        conn.commit()

        while executed < MAX_ACTIONS_PER_TICK:
            case = _case(conn, case_id)

            flag, confidence, technique = _verified_flag(conn, case)
            if flag:
                conn.execute(
                    """
                    UPDATE autopilot_cases
                    SET state='SOLVED',flag=?,confidence=?,blocker=NULL,updated_at=?
                    WHERE id=?
                    """,
                    (flag, confidence, core.now(), case_id),
                )
                _timeline(conn, case_id, f"Verified flag recovered: {flag} ({technique or 'validated evidence'}).", "solved")
                conn.commit()
                break

            actions, reused = _available_actions(conn, case)
            reused_total += reused
            conn.commit()

            if not actions:
                case = _case(conn, case_id)
                if int(case["stage"]) < MAX_STAGE:
                    _strategy_reset(conn, case, "No new action remained at the current analysis depth")
                    conn.commit()
                    continue
                _suspend(
                    conn,
                    case,
                    "No remaining registered analyzer, alternate implementation, transformation, or derived artifact is available. Additional challenge evidence or external infrastructure is required to create a genuinely new action.",
                )
                conn.commit()
                break

            _, row, analysis_id, spec, signature = actions[0]
            label = spec.get("label", analysis_id)
            before_artifacts, before_flags = _counts(conn, case["root_artifact_id"])
            _timeline(conn, case_id, f"Running {label} on {row['filename']}.", "action")

            try:
                result = await wb.execute_analysis(conn, row, analysis_id)
            except Exception as exc:
                result = {
                    "artifact_id": row["id"],
                    "analysis_id": analysis_id,
                    "label": label,
                    "status": "error",
                    "output": f"{type(exc).__name__}: {exc}",
                }

            executed += 1
            failure = _classify_failure(result)
            after_artifacts, after_flags = _counts(conn, case["root_artifact_id"])
            progressed = after_artifacts > before_artifacts or after_flags > before_flags or bool(result.get("artifacts")) or bool(result.get("flags"))

            if failure:
                _record_action(conn, case_id, row, analysis_id, signature, label, "FAILED", failure, _summary(result), result)
                conn.execute(
                    """
                    INSERT INTO autopilot_dead_ends(case_id,artifact_id,analysis_id,reason,revisit_if,created_at)
                    VALUES(?,?,?,?,?,?)
                    """,
                    (
                        case_id, row["id"], analysis_id, failure,
                        "Revisit only if artifact/context/tool availability changes.", core.now(),
                    ),
                )
                conn.execute(
                    "UPDATE autopilot_cases SET state='FALLBACK',stagnation=stagnation+1,updated_at=? WHERE id=?",
                    (core.now(), case_id),
                )
                _timeline(conn, case_id, f"{label} did not solve the path ({failure}). Switching automatically to another justified method.", "fallback")
            else:
                _record_action(conn, case_id, row, analysis_id, signature, label, "SUCCESS", None, _summary(result), result)
                if progressed:
                    conn.execute(
                        "UPDATE autopilot_cases SET state='FOLLOWING_EVIDENCE',stagnation=0,updated_at=? WHERE id=?",
                        (core.now(), case_id),
                    )
                    _timeline(conn, case_id, _summary(result), "progress")
                else:
                    conn.execute(
                        "UPDATE autopilot_cases SET stagnation=stagnation+1,updated_at=? WHERE id=?",
                        (core.now(), case_id),
                    )

            conn.commit()
            case = _case(conn, case_id)
            if int(case["stagnation"]) >= STAGNATION_THRESHOLD:
                _strategy_reset(conn, case, f"{case['stagnation']} consecutive low-information or failed actions")
                conn.commit()

    snap = case_snapshot(case_id)
    snap["tick"] = {"executed_actions": executed, "reused_actions": reused_total}
    return snap


def accept_reasoning_candidate(case_id: int, candidate: str | None, confidence: float, why: str) -> bool:
    if not candidate or confidence < 0.90 or _is_placeholder(candidate):
        return False
    with core.db() as conn:
        case = _case(conn, case_id)
        expected = _expected_prefix(case["description"])
        if expected and not candidate.startswith(expected + "{"):
            return False
        if not re.fullmatch(r"[A-Za-z0-9_-]{2,30}\{[^{}\r\n]{3,200}\}", candidate):
            return False
        conn.execute(
            """
            UPDATE autopilot_cases
            SET state='SOLVED',flag=?,confidence=?,blocker=NULL,updated_at=?
            WHERE id=?
            """,
            (candidate, min(1.0, float(confidence)), core.now(), case_id),
        )
        _timeline(conn, case_id, f"Reasoning correlation produced a verified candidate: {candidate}. {why[:500]}", "solved")
        return True


def case_snapshot(case_id: int) -> dict:
    with core.db() as conn:
        case = _case(conn, case_id)
        rows = _tree_rows(conn, case["root_artifact_id"])
        actions = conn.execute(
            "SELECT state,failure_type,COUNT(*) AS n FROM autopilot_actions WHERE case_id=? GROUP BY state,failure_type",
            (case_id,),
        ).fetchall()
        timeline = conn.execute(
            "SELECT id,level,message,created_at FROM autopilot_timeline WHERE case_id=? ORDER BY id DESC LIMIT 60",
            (case_id,),
        ).fetchall()
        dead = conn.execute(
            "SELECT COUNT(*) AS n FROM autopilot_dead_ends WHERE case_id=?",
            (case_id,),
        ).fetchone()["n"]

        state = case["state"]
        stage = int(case["stage"])
        current_plan = "Verify the recovered candidate flag." if state == "VERIFYING" else (
            "Flag verified; case complete." if state == "SOLVED" else
            f"Continue {STAGE_NAMES.get(stage, 'INVESTIGATION')} and prioritize the highest-information unexplored path."
        )

        return {
            "case_id": int(case["id"]),
            "root_artifact_id": case["root_artifact_id"],
            "title": case["title"],
            "description": case["description"],
            "state": state,
            "stage": stage,
            "stage_name": STAGE_NAMES.get(stage),
            "flag": case["flag"],
            "confidence": float(case["confidence"] or 0),
            "blocker": case["blocker"],
            "stagnation": int(case["stagnation"]),
            "strategy_resets": int(case["strategy_resets"]),
            "artifact_count": len(rows),
            "dead_end_count": int(dead),
            "action_counts": [dict(x) for x in actions],
            "current_plan": current_plan,
            "timeline": [dict(x) for x in reversed(timeline)],
            "updated_at": case["updated_at"],
        }
