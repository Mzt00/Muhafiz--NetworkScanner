"""
consent.py
Manages user opt-in preferences for contributing findings
to the community fingerprint database.
Works with both ExposureFinding and DeviceRiskFinding.
All preferences stored locally in SQLite — never on a server.
"""

import sqlite3
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Union

from core.models import ExposureFinding, DeviceRiskFinding

logger = logging.getLogger(__name__)

DB_PATH    = Path("muhafiz.db")
AnyFinding = Union[ExposureFinding, DeviceRiskFinding]


class ContributeMode(Enum):
    NEVER = "never"   # never contribute, never ask
    ASK   = "ask"     # ask every time (default)
    AUTO  = "auto"    # auto-contribute above threshold

@dataclass
class ConsentDecision:
    allowed: bool
    mode:    ContributeMode
    reason:  str


class ConsentManager:

    def __init__(self):
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS consent_preferences (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS consent_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    port        INTEGER NOT NULL,
                    approved    INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            conn.commit()

        # Set defaults if not already set
        if self.get_mode() is None:
            self.set_mode(ContributeMode.ASK)
        if self.get_auto_threshold() is None:
            self.set_auto_threshold(8)

    def get_consent_for(self, finding: AnyFinding) -> ConsentDecision:
        """
        Returns a ConsentDecision for a given finding.

        ExposureFinding (confirmed mapping) — always eligible
        DeviceRiskFinding (internal only) — only if score >= threshold

        NEVER  → skip silently
        ASK    → show consent dialog
        AUTO   → contribute if risk score meets threshold
        """
        mode      = self.get_mode()
        threshold = self.get_auto_threshold()

        # Hard no
        if mode == ContributeMode.NEVER:
            return ConsentDecision(
                allowed=False,
                mode=mode,
                reason="Contribution disabled in preferences."
            )
        effective_threshold = threshold
        if isinstance(finding, ExposureFinding):
            effective_threshold = max(1, threshold - 2)

        # AUTO mode
        if mode == ContributeMode.AUTO:
            if finding.risk_score >= effective_threshold:
                return ConsentDecision(
                    allowed=True,
                    mode=mode,
                    reason=(
                        f"Auto-contribute: risk score {finding.risk_score} "
                        f">= threshold {effective_threshold}."
                    )
                )
            else:
                return ConsentDecision(
                    allowed=False,
                    mode=mode,
                    reason=(
                        f"Skipped: risk score {finding.risk_score} "
                        f"< threshold {effective_threshold}."
                    )
                )
        return ConsentDecision(
            allowed=False,
            mode=mode,
            reason="User confirmation required — show consent dialog."
        )

    def get_mode(self) -> Optional[ContributeMode]:
        val = self._get("contribute_mode")
        return ContributeMode(val) if val else None

    def set_mode(self, mode: ContributeMode):
        self._set("contribute_mode", mode.value)
        logger.info(f"Contribution mode set to: {mode.value}")

    def get_auto_threshold(self) -> Optional[int]:
        val = self._get("auto_threshold")
        return int(val) if val else None

    def set_auto_threshold(self, score: int):
        if not 1 <= score <= 10:
            raise ValueError("Threshold must be between 1 and 10.")
        self._set("auto_threshold", str(score))
        logger.info(f"Auto-contribute threshold set to: {score}")


    def record_consent(self, port: int, approved: bool):
        """Record that the user approved or declined a contribution."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO consent_log (port, approved) VALUES (?, ?)",
                (port, 1 if approved else 0)
            )
            conn.commit()

    def summary(self) -> dict:
        return {
            "mode":           self.get_mode().value if self.get_mode() else "ask",
            "auto_threshold": self.get_auto_threshold(),
        }

    def _get(self, key: str) -> Optional[str]:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT value FROM consent_preferences WHERE key = ?",
                (key,)
            ).fetchone()
            return row[0] if row else None

    def _set(self, key: str, value: str):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO consent_preferences (key, value) "
                "VALUES (?, ?) ON CONFLICT(key) "
                "DO UPDATE SET value = excluded.value",
                (key, value)
            )
            conn.commit()