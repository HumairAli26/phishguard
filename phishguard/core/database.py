"""
database.py
-------------
Lightweight SQLite persistence layer for scan history. This is what
elevates the project from a one-shot script to a tool with a real
dashboard: every analyzed email is logged so trends can be reviewed later
(e.g. "how many malicious emails did I catch this week?").
"""

from __future__ import annotations

import sqlite3
import json
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_PATH = Path(__file__).resolve().parent.parent / "phishguard_history.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            subject TEXT,
            from_address TEXT,
            score INTEGER,
            verdict TEXT,
            action TEXT,
            red_flags_json TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_scan(subject: str, from_address: str, score: int, verdict: str,
             action: str, red_flags: List[Dict[str, Any]]) -> int:
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO scans (timestamp, subject, from_address, score, verdict, action, red_flags_json)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.datetime.now().isoformat(timespec="seconds"),
            subject, from_address, score, verdict, action, json.dumps(red_flags),
        )
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def fetch_history(limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def verdict_counts() -> Dict[str, int]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT verdict, COUNT(*) as cnt FROM scans GROUP BY verdict"
    ).fetchall()
    conn.close()
    return {row["verdict"]: row["cnt"] for row in rows}


def clear_history() -> None:
    conn = get_connection()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


init_db()
