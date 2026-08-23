from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

from backend import hack4gov_pack as pack
from backend import main as core


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


# The packet analyzers in hack4gov_pack resolve this module global at request
# time, so patch it with the uncapped field registry implementation.
pack.tshark_fields = full_tshark_fields


app = FastAPI(
    title="H4G CTF Workbench - Hack4Gov Runtime",
    version="0.4.3",
    description="Runtime wrapper for the challenge-pack-aware Hack4Gov CTF workbench.",
)


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
        tools.append({"name": "zbarimg", "available": shutil.which("zbarimg") is not None, "path": shutil.which("zbarimg")})
    return tools


def tree_artifact_rows(root_artifact: str | None):
    with core.db() as conn:
        if root_artifact:
            exists = conn.execute("SELECT id FROM artifacts WHERE id=?", (root_artifact,)).fetchone()
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

    return {"query": query, "root_artifact": root_artifact, "artifacts_scanned": scanned, "matches": results}


# All other routes come from the Hack4Gov pack, which in turn mounts the
# expanded challenge pack, recovery layer, and original workbench APIs.
app.mount("/", pack.app)
