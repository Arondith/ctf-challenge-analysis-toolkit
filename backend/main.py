from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import html
import io
import json
import math
import mimetypes
import os
import re
import shutil
import sqlite3
import urllib.parse
import uuid
import zipfile

from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import yaml

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


# ============================================================
# Paths / Configuration
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

WORKSPACE = Path(
    os.getenv("CTF_WORKSPACE", ROOT / "workspace")
)

CONFIG_FILE = Path(
    os.getenv("CTF_CONFIG", ROOT / "config" / "config.yaml")
)

WORKSPACE.mkdir(parents=True, exist_ok=True)
(WORKSPACE / "artifacts").mkdir(parents=True, exist_ok=True)

DB_PATH = WORKSPACE / "ctf.db"

with CONFIG_FILE.open("r", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

MAX_UPLOAD = int(CONFIG["limits"]["max_upload_mb"]) * 1024 * 1024
MAX_DEPTH = int(CONFIG["limits"]["max_artifact_depth"])
MAX_CHILDREN = int(CONFIG["limits"]["max_child_artifacts"])
MAX_EXTRACTED = int(CONFIG["limits"]["max_extracted_size_mb"]) * 1024 * 1024
MAX_DECODE_DEPTH = int(CONFIG["limits"]["max_decode_depth"])


# ============================================================
# Database
# ============================================================

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                parent_id TEXT,
                sha256 TEXT NOT NULL,
                filename TEXT NOT NULL,
                kind TEXT NOT NULL,
                mime TEXT NOT NULL,
                size INTEGER NOT NULL,
                entropy REAL NOT NULL,
                origin TEXT NOT NULL,
                technique TEXT NOT NULL,
                path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_artifact_sha
            ON artifacts(sha256);

            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_id TEXT NOT NULL,
                child_id TEXT NOT NULL,
                technique TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                value TEXT,
                confidence REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT NOT NULL,
                flag TEXT NOT NULL,
                source TEXT NOT NULL,
                technique TEXT NOT NULL,
                confidence REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'possible'
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT,
                action TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            """
        )


def now():
    return datetime.now(timezone.utc).isoformat()


def add_event(conn, artifact_id, action, detail=""):
    conn.execute(
        """
        INSERT INTO events(artifact_id, action, detail, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (artifact_id, action, detail, now()),
    )


# ============================================================
# Utility Functions
# ============================================================

FLAG_PATTERNS = [
    re.compile(r"H4G\{[^}\r\n]{3,200}\}"),
    re.compile(r"HACK4GOV\{[^}\r\n]{3,200}\}", re.I),
    re.compile(r"hack4gov\{[^}\r\n]{3,200}\}", re.I),
    re.compile(r"FLAG\{[^}\r\n]{3,200}\}", re.I),
    re.compile(r"CTF\{[^}\r\n]{3,200}\}", re.I),
    re.compile(r"govctf\{[^}\r\n]{3,200}\}", re.I),
]

GENERIC_FLAG = re.compile(
    r"[A-Za-z0-9_-]{2,30}\{[^}\r\n]{3,200}\}"
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256

    for b in data:
        counts[b] += 1

    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts
        if count
    )


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0

    sample = data[:65536]

    good = sum(
        1
        for b in sample
        if b in (9, 10, 13) or 32 <= b <= 126
    )

    return good / len(sample)


def strings(data: bytes, minimum=4):
    pattern = rb"[\x20-\x7e]{" + str(minimum).encode() + rb",4096}"

    return [
        m.decode("ascii", errors="ignore")
        for m in re.findall(pattern, data)
    ]


def safe_filename(filename: str):
    name = Path(filename or "artifact.bin").name

    name = re.sub(
        r"[^A-Za-z0-9._-]",
        "_",
        name,
    )

    return name[:180] or "artifact.bin"


def safe_archive_path(name: str):
    path = PurePosixPath(
        name.replace("\\", "/")
    )

    if path.is_absolute():
        return False

    if any(
        part in ("", ".", "..")
        for part in path.parts
    ):
        return False

    return True


# ============================================================
# File Identification
# ============================================================

def identify(data: bytes, filename=""):
    signatures = [
        (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
        (b"\xff\xd8\xff", "jpeg", "image/jpeg"),
        (b"GIF87a", "gif", "image/gif"),
        (b"GIF89a", "gif", "image/gif"),
        (b"BM", "bmp", "image/bmp"),
        (b"%PDF", "pdf", "application/pdf"),
        (b"\x7fELF", "elf", "application/x-elf"),
        (b"MZ", "pe", "application/vnd.microsoft.portable-executable"),
        (b"PK\x03\x04", "zip", "application/zip"),
        (b"\x1f\x8b", "gzip", "application/gzip"),
        (b"BZh", "bzip2", "application/x-bzip2"),
        (b"7z\xbc\xaf'\x1c", "7z", "application/x-7z-compressed"),
        (b"Rar!\x1a\x07", "rar", "application/vnd.rar"),
    ]

    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "wav", "audio/wav"

    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcapng", "application/x-pcapng"

    if data[:4] in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    ):
        return "pcap", "application/vnd.tcpdump.pcap"

    for sig, kind, mime in signatures:
        if data.startswith(sig):

            # Detect modern Office containers.
            if kind == "zip":
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        names = set(z.namelist())

                        if "[Content_Types].xml" in names:
                            if any(x.startswith("word/") for x in names):
                                return (
                                    "docx",
                                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                )

                            if any(x.startswith("xl/") for x in names):
                                return (
                                    "xlsx",
                                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                )

                            if any(x.startswith("ppt/") for x in names):
                                return (
                                    "pptx",
                                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                                )

                except zipfile.BadZipFile:
                    pass

            return kind, mime

    guessed, _ = mimetypes.guess_type(filename)

    if guessed and guessed.startswith("text/"):
        return "text", guessed

    if printable_ratio(data) > 0.88:
        return "text", guessed or "text/plain"

    return "unknown", guessed or "application/octet-stream"


# ============================================================
# Flag Detection
# ============================================================

def detect_flags(data: bytes):
    views = [
        data.decode("utf-8", errors="ignore"),
        data.decode("latin-1", errors="ignore"),
    ]

    if data.count(b"\x00") > len(data) // 8:
        views.extend(
            [
                data.decode("utf-16le", errors="ignore"),
                data.decode("utf-16be", errors="ignore"),
            ]
        )

    results = {}

    for text in views:
        for pattern in FLAG_PATTERNS:
            for match in pattern.finditer(text):
                results[match.group(0)] = 0.99

        for match in GENERIC_FLAG.finditer(text):
            results.setdefault(
                match.group(0),
                0.72,
            )

    return sorted(
        results.items(),
        key=lambda x: x[1],
        reverse=True,
    )


# ============================================================
# Recommendations
# ============================================================

def recommend(kind, findings):
    recs = []

    titles = {x["title"] for x in findings}

    if "Embedded ZIP signature" in titles:
        recs.append(
            (
                0.97,
                "Extract appended ZIP",
                "ZIP data appears after the beginning of the file.",
            )
        )

    recs.append(
        (
            0.74,
            "Inspect printable strings",
            "Strings may reveal flags, keys, URLs, paths, or decoder clues.",
        )
    )

    if kind in ("png", "jpeg", "gif", "bmp"):
        recs.extend(
            [
                (
                    0.90,
                    "Extract image metadata",
                    "Image metadata often contains challenge clues.",
                ),
                (
                    0.78,
                    "Inspect LSB and color channels",
                    "Steganographic data may be stored in image bit planes.",
                ),
            ]
        )

    if kind == "wav":
        recs.extend(
            [
                (
                    0.92,
                    "Inspect RIFF/WAV metadata",
                    "Non-audio chunks can contain challenge data.",
                ),
                (
                    0.84,
                    "Generate spectrogram",
                    "Audio CTFs frequently encode visual clues in frequency space.",
                ),
            ]
        )

    if kind in ("pcap", "pcapng"):
        recs.extend(
            [
                (
                    0.96,
                    "Generate protocol statistics",
                    "Identify dominant and unusual protocols.",
                ),
                (
                    0.94,
                    "Search packet payloads for flags",
                    "Flags or fragments may appear in application traffic.",
                ),
                (
                    0.90,
                    "Reconstruct TCP streams",
                    "Transferred messages and files may be recoverable.",
                ),
            ]
        )

    if kind in ("elf", "pe"):
        recs.extend(
            [
                (
                    0.93,
                    "Inspect strings and imports",
                    "Validation routines commonly reference interesting strings or APIs.",
                ),
                (
                    0.86,
                    "Inspect entry point and symbols",
                    "Prioritize comparison and decoding routines.",
                ),
            ]
        )

    if kind in (
        "zip",
        "docx",
        "xlsx",
        "pptx",
        "gzip",
        "rar",
        "7z",
    ):
        recs.append(
            (
                0.96,
                "Recursively inspect archive contents",
                "Extracted children should return to the triage pipeline.",
            )
        )

    return sorted(
        recs,
        reverse=True,
        key=lambda x: x[0],
    )


# ============================================================
# Safe Archive Extraction
# ============================================================

def zip_children(data: bytes):
    children = []
    total = 0

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:

            for info in z.infolist()[:1000]:

                if info.is_dir():
                    continue

                if not safe_archive_path(info.filename):
                    continue

                # Unix symlink check.
                unix_type = (
                    info.external_attr >> 16
                ) & 0o170000

                if unix_type == 0o120000:
                    continue

                if (
                    info.file_size < 0
                    or total + info.file_size > MAX_EXTRACTED
                ):
                    break

                try:
                    child = z.read(info)
                except Exception:
                    continue

                total += len(child)

                children.append(
                    (
                        safe_filename(
                            Path(info.filename).name
                        ),
                        child,
                        "ZIP extraction",
                    )
                )

    except zipfile.BadZipFile:
        pass

    return children


# ============================================================
# File Carving
# ============================================================

def carve(data: bytes):
    children = []

    zip_offset = data.find(
        b"PK\x03\x04",
        1,
    )

    if zip_offset > 0:
        carved = data[zip_offset:]

        if zipfile.is_zipfile(
            io.BytesIO(carved)
        ):
            children.append(
                (
                    f"carved_{zip_offset:08x}.zip",
                    carved,
                    f"File carving at 0x{zip_offset:X}",
                )
            )

    return children


# ============================================================
# Decoder
# ============================================================

def score_text(data):
    score = printable_ratio(data)

    upper = data.upper()

    if (
        b"H4G{" in upper
        or b"CTF{" in upper
        or b"FLAG{" in upper
    ):
        score += 1

    return score


def decode_children(data: bytes):
    if len(data) > 1024 * 1024:
        return []

    candidates = strings(
        data,
        8,
    )

    if printable_ratio(data) > 0.7:
        candidates.insert(
            0,
            data.decode(
                "utf-8",
                errors="ignore",
            ).strip(),
        )

    children = []
    seen = set()

    for text in candidates[:100]:
        raw = text.strip().encode()

        attempts = []

        # Hex
        if (
            len(raw) >= 8
            and len(raw) % 2 == 0
            and re.fullmatch(
                rb"[0-9A-Fa-f]+",
                raw,
            )
        ):
            try:
                attempts.append(
                    (
                        bytes.fromhex(
                            raw.decode()
                        ),
                        "Hex decode",
                    )
                )
            except Exception:
                pass

        # Base64
        if (
            len(raw) >= 12
            and re.fullmatch(
                rb"[A-Za-z0-9+/=_-]+",
                raw,
            )
        ):
            try:
                padded = raw + (
                    b"="
                    * (
                        (4 - len(raw) % 4)
                        % 4
                    )
                )

                attempts.append(
                    (
                        base64.b64decode(
                            padded,
                            validate=False,
                        ),
                        "Base64 decode",
                    )
                )
            except Exception:
                pass

        # Base32
        if (
            len(raw) >= 8
            and re.fullmatch(
                rb"[A-Z2-7=]+",
                raw.upper(),
            )
        ):
            try:
                padded = raw.upper() + (
                    b"="
                    * (
                        (8 - len(raw) % 8)
                        % 8
                    )
                )

                attempts.append(
                    (
                        base64.b32decode(
                            padded,
                            casefold=True,
                        ),
                        "Base32 decode",
                    )
                )
            except Exception:
                pass

        # URL encoding
        if b"%" in raw:
            try:
                attempts.append(
                    (
                        urllib.parse.unquote_to_bytes(
                            raw.decode()
                        ),
                        "URL decode",
                    )
                )
            except Exception:
                pass

        # HTML entities
        if (
            b"&" in raw
            and b";" in raw
        ):
            try:
                attempts.append(
                    (
                        html.unescape(
                            raw.decode()
                        ).encode(),
                        "HTML entity decode",
                    )
                )
            except Exception:
                pass

        for decoded, technique in attempts:

            if (
                not decoded
                or decoded == raw
                or len(decoded) > 25 * 1024 * 1024
            ):
                continue

            digest = sha256_bytes(decoded)

            if digest in seen:
                continue

            if (
                detect_flags(decoded)
                or score_text(decoded)
                > score_text(raw) + 0.1
            ):
                seen.add(digest)

                children.append(
                    (
                        f"decoded_{len(children)+1}.bin",
                        decoded,
                        technique,
                    )
                )

        if len(children) >= 20:
            break

    # Single-byte XOR for small binary challenge data.
    if (
        len(data) <= 4096
        and printable_ratio(data) < 0.65
    ):
        scored = []

        for key in range(256):
            decoded = bytes(
                b ^ key
                for b in data
            )

            score = score_text(decoded)

            if detect_flags(decoded):
                score += 1

            if score >= 0.9:
                scored.append(
                    (
                        score,
                        key,
                        decoded,
                    )
                )

        for score, key, decoded in sorted(
            scored,
            reverse=True,
        )[:3]:

            digest = sha256_bytes(decoded)

            if digest in seen:
                continue

            seen.add(digest)

            children.append(
                (
                    f"xor_{key:02x}.bin",
                    decoded,
                    f"Single-byte XOR key 0x{key:02X}",
                )
            )

    return children[:20]


# ============================================================
# Analysis Pipeline
# ============================================================

class Pipeline:

    def __init__(self, conn):
        self.conn = conn
        self.created = 0

    def link(
        self,
        parent,
        child,
        technique,
    ):
        exists = self.conn.execute(
            """
            SELECT id FROM edges
            WHERE parent_id=?
              AND child_id=?
              AND technique=?
            """,
            (
                parent,
                child,
                technique,
            ),
        ).fetchone()

        if not exists:
            self.conn.execute(
                """
                INSERT INTO edges
                (parent_id, child_id, technique)
                VALUES (?, ?, ?)
                """,
                (
                    parent,
                    child,
                    technique,
                ),
            )

    def technique_chain(self, artifact_id):
        chain = []
        current = artifact_id
        visited = set()

        while current and current not in visited:
            visited.add(current)

            row = self.conn.execute(
                """
                SELECT parent_id, technique
                FROM artifacts
                WHERE id=?
                """,
                (current,),
            ).fetchone()

            if not row:
                break

            chain.append(row["technique"])
            current = row["parent_id"]

        chain.reverse()

        return " → ".join(chain)

    def process(
        self,
        data: bytes,
        filename: str,
        parent=None,
        origin="upload",
        technique="Uploaded artifact",
        depth=0,
    ):
        digest = sha256_bytes(data)

        existing = self.conn.execute(
            """
            SELECT * FROM artifacts
            WHERE sha256=?
            LIMIT 1
            """,
            (digest,),
        ).fetchone()

        if existing:

            if parent:
                self.link(
                    parent,
                    existing["id"],
                    technique,
                )

            add_event(
                self.conn,
                existing["id"],
                "Artifact deduplicated",
                digest,
            )

            return existing["id"]

        if self.created >= MAX_CHILDREN:
            raise RuntimeError(
                "Maximum artifact count reached"
            )

        self.created += 1

        artifact_id = (
            "A-"
            + uuid.uuid4().hex[:8].upper()
        )

        filename = safe_filename(filename)

        artifact_dir = (
            WORKSPACE
            / "artifacts"
            / artifact_id
        )

        artifact_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        file_path = (
            artifact_dir
            / filename
        )

        file_path.write_bytes(data)

        kind, mime = identify(
            data,
            filename,
        )

        ent = entropy(data)

        self.conn.execute(
            """
            INSERT INTO artifacts(
                id,
                parent_id,
                sha256,
                filename,
                kind,
                mime,
                size,
                entropy,
                origin,
                technique,
                path,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact_id,
                parent,
                digest,
                filename,
                kind,
                mime,
                len(data),
                ent,
                origin,
                technique,
                str(file_path),
                now(),
            ),
        )

        if parent:
            self.link(
                parent,
                artifact_id,
                technique,
            )

        add_event(
            self.conn,
            artifact_id,
            "Artifact identified",
            f"{kind} / {mime}",
        )

        findings = []

        findings.append(
            {
                "category": "identity",
                "severity": "info",
                "title": "Magic bytes",
                "value": data[:16].hex(" ").upper(),
                "confidence": 1.0,
            }
        )

        findings.append(
            {
                "category": "entropy",
                "severity": "info",
                "title": "Shannon entropy",
                "value": f"{ent:.3f} bits/byte",
                "confidence": 1.0,
            }
        )

        extracted_strings = strings(data)

        findings.append(
            {
                "category": "strings",
                "severity": "info",
                "title": "Printable strings",
                "value": str(
                    len(extracted_strings)
                ),
                "confidence": 1.0,
            }
        )

        if ent >= 7.3:
            findings.append(
                {
                    "category": "entropy",
                    "severity": "medium",
                    "title": "High entropy",
                    "value": (
                        "May indicate compressed, "
                        "encrypted, or packed data."
                    ),
                    "confidence": 0.75,
                }
            )

        zip_offset = data.find(
            b"PK\x03\x04",
            1,
        )

        if zip_offset > 0:
            findings.append(
                {
                    "category": "carving",
                    "severity": "high",
                    "title": "Embedded ZIP signature",
                    "value": (
                        f"Offset 0x{zip_offset:X}"
                    ),
                    "confidence": 0.97,
                }
            )

        b64_count = sum(
            1
            for s in extracted_strings
            if (
                len(s) >= 12
                and re.fullmatch(
                    r"[A-Za-z0-9+/=_-]+",
                    s,
                )
            )
        )

        if b64_count:
            findings.append(
                {
                    "category": "encoding",
                    "severity": "medium",
                    "title": "Base64-like data detected",
                    "value": str(b64_count),
                    "confidence": 0.67,
                }
            )

        for finding in findings:
            self.conn.execute(
                """
                INSERT INTO findings(
                    artifact_id,
                    category,
                    severity,
                    title,
                    value,
                    confidence
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    finding["category"],
                    finding["severity"],
                    finding["title"],
                    finding["value"],
                    finding["confidence"],
                ),
            )

        # Recommendations.
        for confidence, title, reason in recommend(
            kind,
            findings,
        ):
            self.conn.execute(
                """
                INSERT INTO findings(
                    artifact_id,
                    category,
                    severity,
                    title,
                    value,
                    confidence
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    "recommendation",
                    "info",
                    title,
                    reason,
                    confidence,
                ),
            )

        # Flags.
        for flag, confidence in detect_flags(data):

            exists = self.conn.execute(
                """
                SELECT id FROM flags
                WHERE artifact_id=?
                  AND flag=?
                """,
                (
                    artifact_id,
                    flag,
                ),
            ).fetchone()

            if not exists:
                self.conn.execute(
                    """
                    INSERT INTO flags(
                        artifact_id,
                        flag,
                        source,
                        technique,
                        confidence,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?, 'possible')
                    """,
                    (
                        artifact_id,
                        flag,
                        filename,
                        self.technique_chain(
                            artifact_id
                        ),
                        confidence,
                    ),
                )

                add_event(
                    self.conn,
                    artifact_id,
                    "Possible flag found",
                    flag,
                )

        if depth >= MAX_DEPTH:
            add_event(
                self.conn,
                artifact_id,
                "Recursion limit reached",
                str(depth),
            )

            return artifact_id

        children = []

        if CONFIG["analysis"].get(
            "auto_carve",
            True,
        ):
            children.extend(
                carve(data)
            )

        if (
            CONFIG["analysis"].get(
                "auto_extract_archives",
                True,
            )
            and kind
            in (
                "zip",
                "docx",
                "xlsx",
                "pptx",
            )
        ):
            children.extend(
                zip_children(data)
            )

        if (
            CONFIG["analysis"].get(
                "auto_decode",
                True,
            )
            and depth < MAX_DECODE_DEPTH
        ):
            children.extend(
                decode_children(data)
            )

        seen = set()

        for (
            child_name,
            child_data,
            child_technique,
        ) in children:

            child_hash = sha256_bytes(
                child_data
            )

            if (
                child_hash == digest
                or child_hash in seen
            ):
                continue

            seen.add(child_hash)

            self.process(
                child_data,
                child_name,
                parent=artifact_id,
                origin="derived",
                technique=child_technique,
                depth=depth + 1,
            )

        return artifact_id


# ============================================================
# JSON Helpers
# ============================================================

def artifact_json(conn, row):

    findings = conn.execute(
        """
        SELECT * FROM findings
        WHERE artifact_id=?
        ORDER BY confidence DESC
        """,
        (row["id"],),
    ).fetchall()

    flags = conn.execute(
        """
        SELECT * FROM flags
        WHERE artifact_id=?
        """,
        (row["id"],),
    ).fetchall()

    children = conn.execute(
        """
        SELECT * FROM edges
        WHERE parent_id=?
        """,
        (row["id"],),
    ).fetchall()

    return {
        "id": row["id"],
        "parent_id": row["parent_id"],
        "sha256": row["sha256"],
        "filename": row["filename"],
        "kind": row["kind"],
        "mime": row["mime"],
        "size": row["size"],
        "entropy": round(
            row["entropy"],
            3,
        ),
        "origin": row["origin"],
        "technique": row["technique"],
        "created_at": row["created_at"],

        "children": [
            {
                "id": x["child_id"],
                "technique": x["technique"],
            }
            for x in children
        ],

        "findings": [
            {
                "id": x["id"],
                "category": x["category"],
                "severity": x["severity"],
                "title": x["title"],
                "value": x["value"],
                "confidence": x["confidence"],
            }
            for x in findings
        ],

        "flags": [
            {
                "id": x["id"],
                "flag": x["flag"],
                "source": x["source"],
                "technique": x["technique"],
                "confidence": x["confidence"],
                "status": x["status"],
            }
            for x in flags
        ],
    }


# ============================================================
# WebSocket
# ============================================================

class SocketHub:

    def __init__(self):
        self.clients = set()

    async def broadcast(self, data):

        dead = []

        for client in self.clients:

            try:
                await client.send_json(data)

            except Exception:
                dead.append(client)

        for client in dead:
            self.clients.discard(client)


hub = SocketHub()


# ============================================================
# FastAPI
# ============================================================

init_db()

app = FastAPI(
    title="H4G CTF Challenge Analysis Toolkit",
    version="0.1.0",
)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "tool": "H4G CTF Analyzer",
    }


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):

    data = bytearray()

    while True:

        chunk = await file.read(
            1024 * 1024
        )

        if not chunk:
            break

        data.extend(chunk)

        if len(data) > MAX_UPLOAD:
            raise HTTPException(
                status_code=413,
                detail="Upload exceeds configured limit.",
            )

    if not data:
        raise HTTPException(
            status_code=400,
            detail="Empty file.",
        )

    with db() as conn:

        pipeline = Pipeline(conn)

        artifact_id = pipeline.process(
            bytes(data),
            file.filename or "artifact.bin",
        )

        conn.commit()

        row = conn.execute(
            """
            SELECT * FROM artifacts
            WHERE id=?
            """,
            (artifact_id,),
        ).fetchone()

        result = artifact_json(
            conn,
            row,
        )

    await hub.broadcast(
        {
            "event": "analysis-complete",
            "artifact_id": artifact_id,
        }
    )

    return result


@app.post("/api/demo")
async def demo():

    # Tiny valid PNG.
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
        "AAAAC0lEQVR42mP8/x8AAusB9Wl2nQAAAABJRU5ErkJggg=="
    )

    zbuf = io.BytesIO()

    with zipfile.ZipFile(
        zbuf,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as z:

        z.writestr(
            "message.txt",
            base64.b64encode(
                b"CTF{automatic_triage_works}"
            ),
        )

    payload = (
        png
        + zbuf.getvalue()
    )

    with db() as conn:

        pipeline = Pipeline(conn)

        artifact_id = pipeline.process(
            payload,
            "demo.png",
            origin="demo",
            technique="First-run demo",
        )

        conn.commit()

        row = conn.execute(
            """
            SELECT * FROM artifacts
            WHERE id=?
            """,
            (artifact_id,),
        ).fetchone()

        result = artifact_json(
            conn,
            row,
        )

    await hub.broadcast(
        {
            "event": "analysis-complete",
            "artifact_id": artifact_id,
        }
    )

    return result


@app.get("/api/artifacts")
def artifacts():

    with db() as conn:

        rows = conn.execute(
            """
            SELECT * FROM artifacts
            ORDER BY created_at
            """
        ).fetchall()

        return [
            artifact_json(
                conn,
                row,
            )
            for row in rows
        ]


@app.get(
    "/api/artifacts/{artifact_id}"
)
def artifact(artifact_id: str):

    with db() as conn:

        row = conn.execute(
            """
            SELECT * FROM artifacts
            WHERE id=?
            """,
            (artifact_id,),
        ).fetchone()

        if not row:
            raise HTTPException(
                404,
                "Artifact not found.",
            )

        return artifact_json(
            conn,
            row,
        )


@app.get(
    "/api/artifacts/{artifact_id}/download"
)
def download_artifact(
    artifact_id: str,
):

    with db() as conn:

        row = conn.execute(
            """
            SELECT * FROM artifacts
            WHERE id=?
            """,
            (artifact_id,),
        ).fetchone()

        if not row:
            raise HTTPException(
                404,
                "Artifact not found.",
            )

        path = Path(
            row["path"]
        )

        if not path.is_file():
            raise HTTPException(
                404,
                "Artifact data missing.",
            )

        return FileResponse(
            path,
            filename=row["filename"],
            media_type=row["mime"],
        )


@app.get("/api/flags")
def flags():

    with db() as conn:

        rows = conn.execute(
            """
            SELECT * FROM flags
            ORDER BY id DESC
            """
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]


@app.patch(
    "/api/flags/{flag_id}/{status}"
)
def flag_status(
    flag_id: int,
    status: str,
):

    if status not in (
        "possible",
        "confirmed",
        "false-positive",
    ):
        raise HTTPException(
            400,
            "Invalid status.",
        )

    with db() as conn:

        row = conn.execute(
            """
            SELECT id FROM flags
            WHERE id=?
            """,
            (flag_id,),
        ).fetchone()

        if not row:
            raise HTTPException(
                404,
                "Flag not found.",
            )

        conn.execute(
            """
            UPDATE flags
            SET status=?
            WHERE id=?
            """,
            (
                status,
                flag_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "status": status,
    }


@app.get("/api/events")
def events():

    with db() as conn:

        rows = conn.execute(
            """
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT 250
            """
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]


@app.get("/api/tools")
def tools():

    names = [
        "file",
        "strings",
        "xxd",
        "exiftool",
        "binwalk",
        "foremost",
        "tshark",
        "radare2",
        "rabin2",
        "readelf",
        "objdump",
        "nm",
        "zsteg",
        "steghide",
        "upx",
    ]

    return [
        {
            "name": name,
            "available": (
                shutil.which(name)
                is not None
            ),
            "path": shutil.which(name),
        }
        for name in names
    ]


@app.websocket("/ws")
async def websocket(
    websocket: WebSocket,
):

    await websocket.accept()

    hub.clients.add(websocket)

    try:

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        hub.clients.discard(
            websocket
        )


# Frontend mounted after API routes.
FRONTEND = ROOT / "frontend"

app.mount(
    "/",
    StaticFiles(
        directory=FRONTEND,
        html=True,
    ),
    name="frontend",
)
