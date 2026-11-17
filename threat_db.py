"""Local exact-match phishing feed; stores URL digests, never raw URLs."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DB_PATH = Path(__file__).resolve().parent / "data" / "threats.sqlite3"


def url_digest(url: str) -> str:
    parsed = urlsplit(url.strip())
    host = (parsed.hostname or "").encode("idna").decode("ascii").lower()
    if not host or parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Unsupported URL")
    port = parsed.port
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
        host = f"{host}:{port}"
    normalized = urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def feed_status(path: Path = DB_PATH) -> dict:
    if not path.is_file():
        return {"loaded": False, "count": 0, "updated_at": None, "source": "PhishTank"}
    try:
        with closing(sqlite3.connect(path, timeout=2)) as connection:
            meta = dict(connection.execute("SELECT key, value FROM meta"))
        return {"loaded": True, "count": int(meta.get("count", "0")), "updated_at": meta.get("updated_at"), "source": meta.get("source", "PhishTank")}
    except (sqlite3.Error, ValueError):
        return {"loaded": False, "count": 0, "updated_at": None, "source": "PhishTank"}


def lookup(url: str, path: Path = DB_PATH) -> bool:
    if not path.is_file():
        return False
    try:
        digest = url_digest(url)
        with closing(sqlite3.connect(path, timeout=2)) as connection:
            return connection.execute("SELECT 1 FROM entries WHERE url_hash = ?", (digest,)).fetchone() is not None
    except (ValueError, UnicodeError, sqlite3.Error):
        return False
