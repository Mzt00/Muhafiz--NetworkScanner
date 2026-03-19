"""
history.py

Reads and writes contribution history from SQLite.
Feeds the history panel in the Streamlit dashboard.
"""

import sqlite3
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = Path("muhafiz.db")


@dataclass
class HistoryEntry:
    uuid:           str
    port:           int
    banner_snippet: str
    device_type:    str
    manufacturer:   str
    risk_score:     int
    shodan_match:   bool
    status:         str
    contributed_at: datetime
    updated_at:     datetime


class HistoryTracker:

    def __init__(self):
        self._init_db()


    def _init_db(self):
        """Ensure the contributions table exists."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS contributions (
                    uuid            TEXT PRIMARY KEY,
                    port            INTEGER NOT NULL,
                    banner_snippet  TEXT,
                    device_type     TEXT,
                    manufacturer    TEXT,
                    risk_score      INTEGER,
                    shodan_match    INTEGER,
                    status          TEXT    NOT NULL DEFAULT 'queued',
                    contributed_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
                )
            """)
            conn.commit()

    def get_all(self, limit: int = 50) -> list[HistoryEntry]:
        """
        Returns all contribution history entries
        sorted by most recent first.
        """
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT uuid, port, banner_snippet, device_type,
                       manufacturer, risk_score, shodan_match,
                       status, contributed_at, updated_at
                FROM contributions
                ORDER BY contributed_at DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return [self._row_to_entry(r) for r in rows]


    def get_by_status(self, status: str) -> list[HistoryEntry]:
        """Returns entries filtered by status (pending/merged/queued/failed)."""
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT uuid, port, banner_snippet, device_type,
                       manufacturer, risk_score, shodan_match,
                       status, contributed_at, updated_at
                FROM contributions
                WHERE status = ?
                ORDER BY contributed_at DESC
            """, (status,)).fetchall()

        return [self._row_to_entry(r) for r in rows]

    def get_by_uuid(self, uuid: str) -> Optional[HistoryEntry]:
        """Returns a single entry by its UUID."""
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("""
                SELECT uuid, port, banner_snippet, device_type,
                       manufacturer, risk_score, shodan_match,
                       status, contributed_at, updated_at
                FROM contributions
                WHERE uuid = ?
            """, (uuid,)).fetchone()

        return self._row_to_entry(row) if row else None

    def stats(self) -> dict:
        """
        Returns aggregate contribution stats for the
        dashboard header — total, merged, pending, queued.
        """
        with sqlite3.connect(DB_PATH) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM contributions"
            ).fetchone()[0]

            merged = conn.execute(
                "SELECT COUNT(*) FROM contributions WHERE status = 'merged'"
            ).fetchone()[0]

            pending = conn.execute(
                "SELECT COUNT(*) FROM contributions WHERE status = 'pending'"
            ).fetchone()[0]

            queued = conn.execute(
                "SELECT COUNT(*) FROM contributions WHERE status = 'queued'"
            ).fetchone()[0]

            failed = conn.execute(
                "SELECT COUNT(*) FROM contributions WHERE status = 'failed'"
            ).fetchone()[0]

            last_entry = conn.execute("""
                SELECT contributed_at FROM contributions
                ORDER BY contributed_at DESC LIMIT 1
            """).fetchone()

        return {
            "total":              total,
            "merged":             merged,
            "pending":            pending,
            "queued":             queued,
            "failed":             failed,
            "last_contributed":   last_entry[0] if last_entry else None,
        }


    def delete(self, uuid: str):
        """Remove a contribution record from local history."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "DELETE FROM contributions WHERE uuid = ?", (uuid,)
            )
            conn.commit()
        logger.info(f"Deleted contribution record: {uuid}")

    def clear_all(self):
        """Wipe the entire local contribution history."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM contributions")
            conn.commit()
        logger.info("Cleared all contribution history.")

    def _row_to_entry(self, row: tuple) -> HistoryEntry:
        return HistoryEntry(
            uuid=row[0],
            port=row[1],
            banner_snippet=row[2] or "",
            device_type=row[3] or "unknown",
            manufacturer=row[4] or "unknown",
            risk_score=row[5] or 0,
            shodan_match=bool(row[6]),
            status=row[7],
            contributed_at=datetime.fromisoformat(row[8]),
            updated_at=datetime.fromisoformat(row[9]),
        )