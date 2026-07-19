"""SQLite incident / audit log for SOAR actions."""

import sqlite3
from datetime import datetime

from .config import settings


def init_db() -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def log_incident(target_ip: str, action: str, status: str, details: str = "") -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(
        "INSERT INTO incidents (timestamp, target_ip, action, status, details) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_ip,
            action,
            status,
            details,
        ),
    )
    conn.commit()
    conn.close()


def get_incidents(limit: int = 25) -> list[dict]:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, timestamp, target_ip, action, status, details "
        "FROM incidents ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]
