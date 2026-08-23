from __future__ import annotations

import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from backend import main as core


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _normalize(value: str) -> str:
    value = Path(value).stem.lower()
    value = re.sub(r"(?:__|[_ -])*\(?\d+\)?$", "", value)
    value = re.sub(r"[^a-z0-9]+", "", value)
    return value


def _pretty_filename(value: str) -> str:
    stem = Path(value).stem
    stem = re.sub(r"(?:__|[_ -])*\(?\d+\)?$", "", stem)
    stem = re.sub(r"[_-]+", " ", stem).strip()
    return stem or Path(value).stem


def _docx_paragraphs(path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(path) as zf:
            xml = zf.read("word/document.xml")
    except Exception:
        return []

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []

    out: list[str] = []
    for paragraph in root.iter(f"{{{W_NS}}}p"):
        parts = [node.text or "" for node in paragraph.iter(f"{{{W_NS}}}t")]
        text = "".join(parts).strip()
        if text:
            out.append(text)
    return out


def _challenge_docs() -> list[Path]:
    docs: list[Path] = []
    patterns = [
        "HACK4GOV CHALLENGES-*/HACK4GOV CHALLENGES/HACK4GOV CHALLENGES.docx",
        "**/HACK4GOV CHALLENGES.docx",
    ]
    for pattern in patterns:
        for path in core.ROOT.glob(pattern):
            if path.is_file() and path not in docs:
                docs.append(path)
    return docs[:10]


def _match_bundled_context(filename: str) -> tuple[str | None, str | None]:
    wanted = _normalize(filename)
    if len(wanted) < 4:
        return None, None

    best: tuple[int, str, str] | None = None
    for doc in _challenge_docs():
        paragraphs = _docx_paragraphs(doc)
        for index, paragraph in enumerate(paragraphs):
            candidate = _normalize(paragraph)
            if len(candidate) < 4:
                continue
            if candidate == wanted:
                score = 100
            elif wanted.startswith(candidate) and len(candidate) >= max(5, len(wanted) - 3):
                score = 90
            elif candidate.startswith(wanted) and len(wanted) >= max(5, len(candidate) - 3):
                score = 85
            else:
                continue

            block = [paragraph]
            for following in paragraphs[index + 1:index + 9]:
                block.append(following)
                low = following.lower()
                if "flag format" in low or low.startswith("flag:"):
                    break
            description = "\n".join(block[1:]).strip()
            item = (score, paragraph, description)
            if best is None or item[0] > best[0]:
                best = item
                if score == 100:
                    break
        if best and best[0] == 100:
            break

    if not best:
        return None, None
    return best[1], best[2]


def _case_filenames(root_id: str | None) -> list[str]:
    if not root_id:
        return []
    with core.db() as conn:
        rows = conn.execute(
            """
            WITH RECURSIVE tree(id) AS (
                SELECT ?
                UNION
                SELECT e.child_id FROM edges e JOIN tree t ON e.parent_id=t.id
            )
            SELECT a.filename,a.parent_id,a.created_at
            FROM artifacts a JOIN tree t ON a.id=t.id
            ORDER BY CASE WHEN a.id=? THEN 0 ELSE 1 END, a.created_at
            LIMIT 300
            """,
            (root_id, root_id),
        ).fetchall()
    return [row["filename"] or "" for row in rows if row["filename"]]


def infer_challenge_context(root_id: str | None, title: str, description: str) -> tuple[str, str, str]:
    """Fill missing context from any artifact in the current case tree.

    User-supplied wording always wins. For bundled Hack4Gov cases this can match
    either the root artifact or a member of a multi-file/folder case against the
    bundled challenge document. Arbitrary CTF uploads still fall back to normal
    artifact triage when no bundled-document match exists.
    """
    supplied_title = (title or "").strip()
    supplied_description = (description or "").strip()
    filenames = _case_filenames(root_id)

    matched_title = None
    matched_description = None
    matched_filename = ""
    if not supplied_title or not supplied_description:
        for filename in filenames:
            # Synthetic bundle manifests are useful evidence but not useful titles.
            if filename == "autopilot_case_manifest.json":
                continue
            mt, md = _match_bundled_context(filename)
            if mt:
                matched_title, matched_description, matched_filename = mt, md, filename
                break

    display_filename = matched_filename or next(
        (name for name in filenames if name != "autopilot_case_manifest.json"),
        filenames[0] if filenames else "",
    )
    final_title = supplied_title or matched_title or (_pretty_filename(display_filename) if display_filename else "Untitled challenge")
    final_description = supplied_description or matched_description or ""

    if supplied_description:
        source = "user"
    elif matched_description:
        source = "bundled-challenge-document"
    elif display_filename:
        source = "artifact-filename-only"
    else:
        source = "none"

    return final_title, final_description, source
