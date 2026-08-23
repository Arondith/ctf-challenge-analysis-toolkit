from __future__ import annotations

import os

from backend import main as core
from backend import workbench as wb

MAX_AUTO_ACTIONS = int(os.getenv("H4G_AUTO_MAX_ACTIONS", "180"))
MAX_AUTO_ARTIFACTS = int(os.getenv("H4G_AUTO_MAX_ARTIFACTS", "120"))
MAX_AUTO_PASSES = int(os.getenv("H4G_AUTO_MAX_PASSES", "6"))


def _tree_ids(conn, root_id: str) -> list[str]:
    rows = conn.execute(
        """
        WITH RECURSIVE tree(id) AS (
            SELECT ?
            UNION
            SELECT e.child_id
            FROM edges e
            JOIN tree t ON e.parent_id=t.id
        )
        SELECT id FROM tree LIMIT ?
        """,
        (root_id, MAX_AUTO_ARTIFACTS),
    ).fetchall()
    return [row["id"] for row in rows]


def _previous_run(conn, artifact_id: str, analysis_id: str):
    return conn.execute(
        """
        SELECT id, status, returncode
        FROM tool_runs
        WHERE artifact_id=? AND analysis_id=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (artifact_id, analysis_id),
    ).fetchone()


def _is_reusable(previous) -> bool:
    if not previous:
        return False
    # A completed run is evidence and should not be needlessly rerun every time
    # the Solve button is pressed. Missing/error/timeout runs are retried so a
    # newly rebuilt image or newly installed tool can recover automatically.
    return previous["status"] == "complete"


async def run_autonomous_analysis(root_id: str) -> dict:
    """Run bounded, allow-listed automatic analyzers across a challenge tree.

    Completed historical analysis is reused as evidence. New analyzers and prior
    missing/error/timeout analyses are executed. Newly produced child artifacts
    enter the next pass automatically.
    """

    actions = 0
    reused = 0
    retrying = 0
    artifacts_seen: set[str] = set()
    results: list[dict] = []
    stopped_reason = "no-new-actions"

    with core.db() as conn:
        exists = conn.execute("SELECT id FROM artifacts WHERE id=?", (root_id,)).fetchone()
        if not exists:
            return {
                "root_artifact_id": root_id,
                "actions": 0,
                "reused_actions": 0,
                "retried_actions": 0,
                "artifacts_seen": 0,
                "passes": 0,
                "stopped_reason": "root-not-found",
                "results": [],
            }

        completed_passes = 0

        for pass_no in range(1, MAX_AUTO_PASSES + 1):
            completed_passes = pass_no
            pass_actions = 0
            artifact_ids = _tree_ids(conn, root_id)

            for artifact_id in artifact_ids:
                if actions >= MAX_AUTO_ACTIONS:
                    stopped_reason = "action-budget"
                    break

                try:
                    row = wb.artifact_row(conn, artifact_id)
                except Exception as exc:
                    results.append(
                        {
                            "artifact_id": artifact_id,
                            "analysis_id": "artifact.open",
                            "status": "error",
                            "output": f"{type(exc).__name__}: {exc}",
                        }
                    )
                    continue

                artifacts_seen.add(artifact_id)
                catalog = wb.analysis_catalog(row)

                for analysis_id, spec in catalog.items():
                    if actions >= MAX_AUTO_ACTIONS:
                        stopped_reason = "action-budget"
                        break
                    if not spec.get("auto"):
                        continue

                    previous = _previous_run(conn, artifact_id, analysis_id)
                    if _is_reusable(previous):
                        reused += 1
                        continue
                    if previous:
                        retrying += 1

                    try:
                        result = await wb.execute_analysis(conn, row, analysis_id)
                    except Exception as exc:
                        result = {
                            "artifact_id": artifact_id,
                            "analysis_id": analysis_id,
                            "label": spec.get("label", analysis_id),
                            "status": "error",
                            "output": f"{type(exc).__name__}: {exc}",
                        }

                    result.setdefault("artifact_id", artifact_id)
                    results.append(result)
                    actions += 1
                    pass_actions += 1
                    conn.commit()

            if actions >= MAX_AUTO_ACTIONS:
                break

            # Re-query on the next pass so newly extracted/repaired/generated
            # children automatically enter the same solve session.
            if pass_actions == 0:
                stopped_reason = "all-current-analysis-reused" if reused else "no-new-actions"
                break
            stopped_reason = "pass-limit"

        core.add_event(
            conn,
            root_id,
            "Autonomous analysis pass",
            (
                f"{actions} new analyzer action(s), {reused} completed action(s) reused, "
                f"{retrying} retried, {len(artifacts_seen)} artifact(s), stopped={stopped_reason}"
            ),
        )
        conn.commit()

    compact = []
    for item in results[-80:]:
        compact.append(
            {
                "artifact_id": item.get("artifact_id"),
                "analysis_id": item.get("analysis_id"),
                "label": item.get("label"),
                "status": item.get("status"),
                "flags": item.get("flags", []),
                "artifacts": item.get("artifacts", []),
            }
        )

    return {
        "root_artifact_id": root_id,
        "actions": actions,
        "reused_actions": reused,
        "retried_actions": retrying,
        "artifacts_seen": len(artifacts_seen),
        "passes": completed_passes,
        "stopped_reason": stopped_reason,
        "results": compact,
    }
