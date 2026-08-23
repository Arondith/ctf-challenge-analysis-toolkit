from __future__ import annotations

import json
import re
from pathlib import Path

from backend import main as core


def ensure_state_db() -> None:
    with core.db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS autopilot_targets (
                case_id INTEGER PRIMARY KEY,
                answer_type TEXT NOT NULL,
                flag_prefix TEXT,
                requirements_json TEXT NOT NULL,
                completion_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS autopilot_hypotheses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                hypothesis_key TEXT NOT NULL,
                statement TEXT NOT NULL,
                confidence REAL NOT NULL,
                status TEXT NOT NULL,
                evidence TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE(case_id, hypothesis_key)
            );

            CREATE INDEX IF NOT EXISTS idx_autopilot_hypotheses_case
            ON autopilot_hypotheses(case_id, confidence DESC);
            """
        )


ensure_state_db()


def _tree(conn, root_id: str):
    return conn.execute(
        """
        WITH RECURSIVE tree(id) AS (
            SELECT ?
            UNION
            SELECT e.child_id FROM edges e JOIN tree t ON e.parent_id=t.id
        )
        SELECT a.* FROM artifacts a JOIN tree t ON a.id=t.id
        ORDER BY a.created_at LIMIT 300
        """,
        (root_id,),
    ).fetchall()


def _target_from_context(title: str, description: str) -> tuple[str, str | None, dict]:
    text = f"{title}\n{description}".lower()
    prefix_match = re.search(r"(?i)flag\s*format\s*:\s*([A-Za-z0-9_-]+)\{", description or "")
    prefix = prefix_match.group(1) if prefix_match else None

    if "message-id" in text or "message id" in text:
        return "email_header", prefix, {"field": "Message-ID", "components": ["message_id"]}
    if "closest" in text and "farthest" in text and "coordinate" in text:
        return "coordinate_relationship", prefix, {"components": ["closest_pair", "farthest_pair"]}
    if "five different protocols" in text or "part1_part2_part3_part4_part5" in text:
        return "multipart_protocol_flag", prefix, {"components": ["http", "mail", "dns", "icmp", "source"]}
    if "locate all ships" in text or ("grid" in text and any(x in text for x in ("ship", "sonar", "cell"))):
        return "grid_coordinates", prefix, {"components": ["all_target_cells"]}
    if "sha256" in text or "sha-256" in text:
        return "hash_answer", prefix, {"components": ["sha256"]}
    if any(x in text for x in ("what malware", "what is the name", "who is", "when was", "what date")):
        return "knowledge_or_osint_answer", prefix, {"components": ["semantic_answer"]}
    return "literal_or_derived_flag", prefix, {"components": ["verified_flag"]}


def _completion(conn, case_id: int, root_id: str, requirements: dict) -> dict:
    rows = _tree(conn, root_id)
    ids = [r["id"] for r in rows]
    complete = {component: False for component in requirements.get("components", [])}
    if not ids:
        return complete
    marks = ",".join("?" for _ in ids)
    flags = conn.execute(
        f"SELECT flag,confidence,status FROM flags WHERE artifact_id IN ({marks}) AND status!='false-positive'",
        ids,
    ).fetchall()
    if "verified_flag" in complete and any((f["status"] == "confirmed" or float(f["confidence"] or 0) >= 0.95) for f in flags):
        complete["verified_flag"] = True

    runs = conn.execute(
        f"SELECT analysis_id,label,output FROM tool_runs WHERE artifact_id IN ({marks}) ORDER BY id DESC LIMIT 300",
        ids,
    ).fetchall()
    joined = "\n".join((r["analysis_id"] or "") + "\n" + (r["label"] or "") + "\n" + (r["output"] or "")[:10000] for r in runs).lower()
    token_map = {
        "message_id": ("message-id", "message id"),
        "closest_pair": ("closest pair",),
        "farthest_pair": ("farthest pair",),
        "http": ("http",),
        "mail": ("smtp", "mail", "imf"),
        "dns": ("dns",),
        "icmp": ("icmp",),
        "source": ("source", "ftp"),
        "all_target_cells": ("minority cluster coordinates", "target cells", "grid"),
        "sha256": ("sha256", "sha-256"),
    }
    for component in list(complete):
        tokens = token_map.get(component, ())
        if tokens and any(token in joined for token in tokens):
            complete[component] = True
    return complete


def _upsert_hypothesis(conn, case_id: int, key: str, statement: str, confidence: float, evidence: str, status: str = "ACTIVE"):
    conn.execute(
        """
        INSERT INTO autopilot_hypotheses(case_id,hypothesis_key,statement,confidence,status,evidence,updated_at)
        VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(case_id,hypothesis_key) DO UPDATE SET
            statement=excluded.statement,
            confidence=excluded.confidence,
            status=excluded.status,
            evidence=excluded.evidence,
            updated_at=excluded.updated_at
        """,
        (case_id, key, statement, max(0.0, min(1.0, confidence)), status, evidence[:2000], core.now()),
    )


def refresh_case_reasoning_state(case_id: int) -> dict:
    with core.db() as conn:
        case = conn.execute("SELECT * FROM autopilot_cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            raise ValueError("Autopilot case not found")
        artifacts = _tree(conn, case["root_artifact_id"])
        answer_type, prefix, requirements = _target_from_context(case["title"], case["description"])
        completion = _completion(conn, case_id, case["root_artifact_id"], requirements)
        conn.execute(
            """
            INSERT INTO autopilot_targets(case_id,answer_type,flag_prefix,requirements_json,completion_json,updated_at)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(case_id) DO UPDATE SET
                answer_type=excluded.answer_type,
                flag_prefix=excluded.flag_prefix,
                requirements_json=excluded.requirements_json,
                completion_json=excluded.completion_json,
                updated_at=excluded.updated_at
            """,
            (case_id, answer_type, prefix, json.dumps(requirements), json.dumps(completion), core.now()),
        )

        kinds = {r["kind"] for r in artifacts}
        names = " ".join(r["filename"] for r in artifacts).lower()
        run_rows = conn.execute(
            """
            WITH RECURSIVE tree(id) AS (
                SELECT ? UNION SELECT e.child_id FROM edges e JOIN tree t ON e.parent_id=t.id
            )
            SELECT tr.output FROM tool_runs tr JOIN tree t ON tr.artifact_id=t.id
            ORDER BY tr.id DESC LIMIT 120
            """,
            (case["root_artifact_id"],),
        ).fetchall()
        run_text = "\n".join((r["output"] or "")[:4000] for r in run_rows).lower()

        candidates = []
        if "pe" in kinds or any(name.endswith(".exe") for name in names.split()):
            candidates.append(("binary_logic", "The executable contains or constructs the challenge success/validation logic.", 0.64, "PE/executable artifact present"))
        if any(marker in run_text for marker in ("pyinstaller", "pyi-python-flag", "possible entry point")):
            candidates.append(("pyinstaller", "The executable is a PyInstaller application whose Python code/resources should be reconstructed.", 0.95, "PyInstaller markers in analyzer evidence"))
        if "wav" in kinds:
            candidates.append(("audio_encoding", "Audio carries structured challenge information rather than ordinary sound alone.", 0.68, "WAV artifact present"))
        if any(token in run_text for token in ("frequency grid", "minority cluster", "repeated-tone")):
            candidates.append(("tone_grid", "Repeated audio tones encode states/cells that must be reconstructed into a grid or ordered sequence.", 0.94, "Tone/grid analyzer evidence"))
        if "pcap" in kinds or "pcapng" in kinds:
            candidates.append(("network_evidence", "The answer is recoverable from protocol streams, payloads, or transferred objects in the capture.", 0.75, "Packet capture artifact present"))
        if any(k in kinds for k in ("png", "jpeg", "gif", "bmp")):
            candidates.append(("image_hidden_data", "One or more images may carry hidden, layered, encoded, or visual-cryptography evidence.", 0.48, "Image artifact present"))
        if "zip" in kinds or any(x.endswith(".zip") for x in names.split()):
            candidates.append(("archive_chain", "The challenge uses an archive/container chain whose members must be followed recursively.", 0.66, "Archive artifact present"))
        if answer_type == "knowledge_or_osint_answer":
            candidates.append(("semantic_clue", "Challenge wording itself is likely decisive and should be correlated with technical/general knowledge.", 0.82, "Solve target is semantic/knowledge based"))
        if not candidates:
            candidates.append(("generic_carrier", "The supplied artifact is a carrier or clue that requires structural triage before the answer path is known.", 0.50, "No dominant family established yet"))

        active_keys = set()
        for key, statement, confidence, evidence in candidates:
            active_keys.add(key)
            _upsert_hypothesis(conn, case_id, key, statement, confidence, evidence)
        if active_keys:
            marks = ",".join("?" for _ in active_keys)
            conn.execute(
                f"UPDATE autopilot_hypotheses SET status='LOW_PRIORITY' WHERE case_id=? AND hypothesis_key NOT IN ({marks})",
                [case_id, *active_keys],
            )
        conn.commit()

    return reasoning_state_snapshot(case_id)


def reasoning_state_snapshot(case_id: int) -> dict:
    with core.db() as conn:
        target = conn.execute("SELECT * FROM autopilot_targets WHERE case_id=?", (case_id,)).fetchone()
        hypotheses = conn.execute(
            "SELECT hypothesis_key,statement,confidence,status,evidence,updated_at FROM autopilot_hypotheses WHERE case_id=? ORDER BY confidence DESC LIMIT 12",
            (case_id,),
        ).fetchall()
        return {
            "solve_target": None if not target else {
                "answer_type": target["answer_type"],
                "flag_prefix": target["flag_prefix"],
                "requirements": json.loads(target["requirements_json"]),
                "completion": json.loads(target["completion_json"]),
            },
            "hypotheses": [dict(x) for x in hypotheses],
        }
