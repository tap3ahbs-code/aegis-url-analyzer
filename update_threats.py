"""Refresh the local PhishTank exact-match database, without visiting listed URLs."""

from __future__ import annotations

import argparse
import csv
import io
import os
import sqlite3
import urllib.request
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from threat_db import DB_PATH, url_digest

FEED_URL = "https://data.phishtank.com/data/online-valid.csv"
USER_AGENT = "Aegis-school-project/1.0 (local URL research)"


def import_csv(stream, destination: Path = DB_PATH, source: str = "PhishTank") -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_suffix(".new")
    temp.unlink(missing_ok=True)
    count = 0
    try:
        with closing(sqlite3.connect(temp)) as connection:
            with connection:
                connection.execute("CREATE TABLE entries (url_hash TEXT PRIMARY KEY)")
                connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                reader = csv.DictReader(stream)
                if not reader.fieldnames or "url" not in reader.fieldnames:
                    raise ValueError("The feed has no URL column")
                for row in reader:
                    try:
                        digest = url_digest(row["url"])
                    except (ValueError, UnicodeError, TypeError):
                        continue
                    connection.execute("INSERT OR IGNORE INTO entries(url_hash) VALUES (?)", (digest,))
                count = connection.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
                if count == 0:
                    raise ValueError("The feed is empty")
                meta = {"source": source, "count": str(count), "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
                connection.executemany("INSERT INTO meta(key,value) VALUES (?,?)", meta.items())
        os.replace(temp, destination)
    finally:
        temp.unlink(missing_ok=True)
    return count


def main():
    parser = argparse.ArgumentParser(description="Update local phishing URL digests")
    parser.add_argument("--file", type=Path, help="Import a local CSV file instead of downloading PhishTank")
    args = parser.parse_args()
    if args.file:
        with args.file.open("r", encoding="utf-8-sig", newline="") as stream:
            count = import_csv(stream, source="Local CSV")
    else:
        request = urllib.request.Request(FEED_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=45) as response:
            stream = io.TextIOWrapper(response, encoding="utf-8-sig", newline="")
            count = import_csv(stream)
    print(f"Imported {count} URL digests into {DB_PATH}")


if __name__ == "__main__":
    main()
