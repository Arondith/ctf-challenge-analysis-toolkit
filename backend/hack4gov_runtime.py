from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

from backend import hack4gov_pack as pack
from backend import main as core
from backend.autonomous_solver_router import router as solve_router


def full_tshark_fields() -> set[str]:
    """Read tshark's field registry without the UI output truncation limit."""
    tool = shutil.which("tshark")
    if not tool:
        return set()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/tmp",
    }
    try:
        completed = subprocess.run(
            [tool, "-G", "fields"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
    except Exception:
        return set()
    if completed.returncode != 0:
        return set()
    text = completed.stdout.decode("utf-8", errors="replace")
    fields: set[str] = set()
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            fields.add(parts[2])
    return fields


def strict_detect_flags(data: bytes):
    """Prefer real printable CTF flags and avoid compressed-binary brace noise."""
    printable_stream = "\n".join(core.strings(data, 4))
    views = [printable_stream]
    if core.printable_ratio(data) >= 0.65:
        views.insert(0, data.decode("utf-8", errors="ignore"))
    if data.count(b"\x00") > len(data) // 8:
        views.extend(
            [
                data.decode("utf-16le", errors="ignore"),
                data.decode("utf-16be", errors="ignore"),
            ]
        )

    results: dict[str, float] = {}

    def acceptable(value: str, generic: bool = False) -> bool:
        if not value.isascii() or not value.isprintable():
            return False
        if "{" not in value or not value.endswith("}"):
            return False
        body = value.split("{", 1)[1][:-1]
        if len(body) < (5 if generic else 3):
            return False
        if not any(ch.isalnum() for ch in body):
            return False
        if generic:
            useful = sum(ch.isalnum() or ch in "_-@!$%+." for ch in body)
            if useful / max(1, len(body)) < 0.65:
                return False
        return True

    for text in views:
        for pattern in core.FLAG_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                if acceptable(value):
                    results[value] = 0.99
        for match in core.GENERIC_FLAG.finditer(text):
            value = match.group(0)
            if acceptable(value, generic=True):
                results.setdefault(value, 0.55)

    return sorted(results.items(), key=lambda x: x[1], reverse=True)


def prune_binary_flag_noise() -> int:
    """Remove previously stored candidates that fail the stricter detector."""
    removed = 0
    with core.db() as conn:
        rows = conn.execute("SELECT id, flag, status FROM flags").fetchall()
        for row in rows:
            if row["status"] == "confirmed":
                continue
            flag = row["flag"] or ""
            valid = bool(strict_detect_flags(flag.encode("utf-8", errors="ignore")))
            if not valid:
                conn.execute("DELETE FROM flags WHERE id=?", (row["id"],))
                removed += 1
        if removed:
            core.add_event(
                conn,
                None,
                "Flag candidate cleanup",
                f"Removed {removed} binary/noisy regex false positives",
            )
    return removed


# Runtime patches used by every mounted analyzer route.
pack.tshark_fields = full_tshark_fields
core.detect_flags = strict_detect_flags
prune_binary_flag_noise()


app = FastAPI(
    title="H4G CTF Workbench - Hack4Gov Runtime",
    version="0.6.0",
    description="Runtime wrapper for the challenge-pack-aware Hack4Gov CTF workbench.",
)
app.include_router(solve_router)


@app.get("/api/h4g/coverage")
def runtime_coverage():
    base = pack.h4g_coverage()
    features = list(base.get("features", []))
    features.extend(
        [
            "Solve Assistant with saved how-it-was-solved reports",
            "bounded autonomous analyzer execution across the challenge artifact tree",
            "enhanced solve-first reasoning with backend-only configuration",
            "strict printable flag filtering and legacy false-positive cleanup",
        ]
    )
    return {**base, "version": "0.6.0", "features": features}


@app.get("/workbench", response_class=HTMLResponse)
def expanded_workbench():
    """Serve the existing workbench with a larger challenge-tree budget."""
    path = core.ROOT / "frontend" / "workbench.html"
    html = path.read_text(encoding="utf-8")
    html = html.replace("while(pass<5&&total<60)", "while(pass<8&&total<250)")
    html = html.replace("if(total>=60)break", "if(total>=250)break")

    needle = '<button id="newChallenge" class="danger">New Challenge</button>'
    replacement = (
        '<a href="/challenge-library"><button>Challenge Library</button></a>'
        '<a href="/solve-assistant"><button>Solve Assistant</button></a>'
        '<a href="/case-search"><button>Case Search</button></a>'
        '<a href="/visual-crypto"><button>Visual Crypto</button></a>'
        + needle
    )
    html = html.replace(needle, replacement)
    return HTMLResponse(html)


@app.get("/case-search")
def case_search_page():
    return FileResponse(core.ROOT / "frontend" / "case_search.html")


@app.get("/api/tools")
def hack4gov_tools():
    tools = list(pack.base.expanded_tools())
    names = {x.get("name") for x in tools}
    if "zbarimg" not in names:
        tools.append(
            {
                "name": "zbarimg",
                "available": shutil.which("zbarimg") is not None,
                "path": shutil.which("zbarimg"),
            }
        )
    return tools


def tree_artifact_rows(root_artifact: str | None):
    with core.db() as conn:
        if root_artifact:
            exists = conn.execute(
                "SELECT id FROM artifacts WHERE id=?",
                (root_artifact,),
            ).fetchone()
            if not exists:
                raise HTTPException(404, "Root artifact not found.")
            rows = conn.execute(
                """
                WITH RECURSIVE tree(id) AS (
                    SELECT ?
                    UNION
                    SELECT e.child_id FROM edges e JOIN tree t ON e.parent_id=t.id
                )
                SELECT a.* FROM artifacts a JOIN tree t ON a.id=t.id
                ORDER BY a.created_at
                LIMIT 300
                """,
                (root_artifact,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE origin!='demo' ORDER BY created_at DESC LIMIT 300"
            ).fetchall()
        return [dict(x) for x in rows]


@app.get("/api/h4g/case-search")
def case_search(q: str, root_artifact: str | None = None):
    query = (q or "").strip()
    if len(query) < 2:
        raise HTTPException(400, "Search query must contain at least 2 characters.")
    needle = query.lower()
    results = []
    scanned = 0

    for row in tree_artifact_rows(root_artifact):
        path = Path(row["path"])
        if not path.is_file():
            continue
        scanned += 1
        try:
            with path.open("rb") as f:
                data = f.read(2 * 1024 * 1024)
        except OSError:
            continue

        sample = data[:32768]
        if core.printable_ratio(sample) > 0.45:
            text = data.decode("utf-8", errors="replace")
        else:
            text = "\n".join(core.strings(data, 4)[:5000])

        lower = text.lower()
        start = 0
        hit_count = 0
        while True:
            pos = lower.find(needle, start)
            if pos < 0:
                break
            left = max(0, pos - 180)
            right = min(len(text), pos + len(query) + 260)
            snippet = text[left:right].replace("\x00", "")
            results.append(
                {
                    "artifact_id": row["id"],
                    "filename": row["filename"],
                    "kind": row["kind"],
                    "origin": row["origin"],
                    "technique": row["technique"],
                    "snippet": snippet,
                }
            )
            hit_count += 1
            start = pos + max(1, len(query))
            if hit_count >= 5 or len(results) >= 100:
                break
        if len(results) >= 100:
            break

    return {
        "query": query,
        "root_artifact": root_artifact,
        "artifacts_scanned": scanned,
        "matches": results,
    }


# All other routes come from the Hack4Gov pack, which in turn mounts the
# expanded challenge pack, recovery layer, and original workbench APIs.
app.mount("/", pack.app)
