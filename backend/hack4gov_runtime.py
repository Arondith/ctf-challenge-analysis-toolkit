from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from backend import hack4gov_pack as pack
from backend import main as core


app = FastAPI(
    title="H4G CTF Workbench - Hack4Gov Runtime",
    version="0.4.1",
    description="Runtime wrapper for the challenge-pack-aware Hack4Gov CTF workbench.",
)


@app.get("/workbench", response_class=HTMLResponse)
def expanded_workbench():
    """Serve the existing workbench with a larger challenge-tree budget.

    The stock integrated workbench intentionally caps recursive browser-driven
    runs at 60 artifacts. The real Hack4Gov example pack includes folders with
    100+ related images, so the Hack4Gov runtime raises that cap to 250 and
    allows additional discovery passes without duplicating the entire UI file.
    """
    path = core.ROOT / "frontend" / "workbench.html"
    html = path.read_text(encoding="utf-8")
    html = html.replace("while(pass<5&&total<60)", "while(pass<8&&total<250)")
    html = html.replace("if(total>=60)break", "if(total>=250)break")

    # Add navigation to the challenge-pack helpers while preserving the
    # existing buttons and behavior.
    needle = '<button id="newChallenge" class="danger">New Challenge</button>'
    replacement = (
        '<a href="/challenge-library"><button>Challenge Library</button></a>'
        '<a href="/visual-crypto"><button>Visual Crypto</button></a>'
        + needle
    )
    html = html.replace(needle, replacement)
    return HTMLResponse(html)


# All other routes come from the Hack4Gov pack, which in turn mounts the
# expanded challenge pack, recovery layer, and original workbench APIs.
app.mount("/", pack.app)
