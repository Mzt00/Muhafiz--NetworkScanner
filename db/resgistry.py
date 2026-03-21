"""
registry.py
Exposed Device Registry
Tracks every device that has ever been found exposed,
keyed by MAC prefix so devices are recognised across
scans even when their IP changes (DHCP).
Lives in db/ and is used by the analysis engine after
each scan to update the registry.
"""

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import ScanResult

logger = logging.getLogger(__name__)

# Always resolve relative to the project root regardless of
# where Python's working directory is at runtime
DB_PATH = Path("muhafiz.db")


@dataclass
class RegistryEntry:
    id:                 int
    mac_prefix:         str
    last_ip:            str
    hostname:           str
    device_type:        str
    manufacturer:       str
    exposed_ports:      list[int]
    highest_risk_score: int
    exposure_count:     int
    first_exposed:      datetime
    last_exposed:       datetime
    is_new:             bool
    resolved:           bool



@dataclass
class ChangelogEntry:
    mac_prefix:  str
    event:       str
    detail:      str
    risk_score:  int
    recorded_at: datetime


class DeviceRegistry:

    def __init__(self):
        self._init_db()


    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS exposed_device_registry (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_prefix          TEXT    NOT NULL UNIQUE,
                    last_ip             TEXT    NOT NULL,
                    hostname            TEXT,
                    device_type         TEXT    NOT NULL DEFAULT 'unknown',
                    manufacturer        TEXT    NOT NULL DEFAULT 'unknown',
                    exposed_ports       TEXT    NOT NULL DEFAULT '[]',
                    highest_risk_score  INTEGER NOT NULL DEFAULT 0,
                    exposure_count      INTEGER NOT NULL DEFAULT 0,
                    first_exposed       TEXT    NOT NULL DEFAULT (datetime('now')),
                    last_exposed        TEXT    NOT NULL DEFAULT (datetime('now')),
                    last_scan_id        INTEGER,
                    is_new              INTEGER NOT NULL DEFAULT 1,
                    resolved            INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS registry_changelog (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_prefix  TEXT    NOT NULL,
                    scan_id     INTEGER NOT NULL,
                    event       TEXT    NOT NULL,
                    detail      TEXT,
                    risk_score  INTEGER NOT NULL DEFAULT 0,
                    recorded_at TEXT    NOT NULL DEFAULT (datetime('now'))
                )
            """)
            conn.commit()

    def update(self, result: ScanResult, scan_id: int):
        """
        Called after each scan completes.
        For every critical correlation found:
          - If device is new to registry → insert + log 'first_seen'
          - If device already exists:
              - If new port found → log 'new_port'
              - Otherwise → log 'still_exposed'
          - Updates exposure_count, last_exposed, risk score
        """
        for correlation in result.correlations:
            device   = correlation.device
            mac_prefix = ":".join(device.mac.split(":")[:3]) if device.mac else "unknown"
            ports    = [op.port for op in device.ports]
            existing = self._get_by_mac(mac_prefix)

            if existing is None:
                # Brand new exposed device
                self._insert(
                    mac_prefix=mac_prefix,
                    ip=device.ip,
                    hostname=device.hostname,
                    device_type=correlation.device.ports[0].device_type if device.ports else "unknown",
                    manufacturer=correlation.device.ports[0].manufacturer if device.ports else "unknown",
                    ports=ports,
                    risk_score=correlation.risk_score,
                    scan_id=scan_id,
                )
                self._log(
                    mac_prefix=mac_prefix,
                    scan_id=scan_id,
                    event="first_seen",
                    detail=f"Device first detected as exposed — {correlation.device.ports[0].manufacturer if device.ports else 'unknown'} on port(s) {ports}",
                    risk_score=correlation.risk_score,
                )
                logger.warning(f"NEW exposed device in registry: {mac_prefix} ({device.ip})")

            else:
                # Device seen before — check for new ports
                existing_ports = set(existing["exposed_ports"])
                new_ports      = [p for p in ports if p not in existing_ports]
                all_ports      = list(existing_ports | set(ports))

                if new_ports:
                    self._log(
                        mac_prefix=mac_prefix,
                        scan_id=scan_id,
                        event="new_port",
                        detail=f"New exposed port(s) detected: {new_ports}",
                        risk_score=correlation.risk_score,
                    )
                    logger.warning(f"New port(s) {new_ports} on known exposed device {mac_prefix}")
                else:
                    self._log(
                        mac_prefix=mac_prefix,
                        scan_id=scan_id,
                        event="still_exposed",
                        detail=f"Device still exposed on port(s) {ports}",
                        risk_score=correlation.risk_score,
                    )

                self._update(
                    mac_prefix=mac_prefix,
                    ip=device.ip,
                    hostname=device.hostname,
                    ports=all_ports,
                    risk_score=max(correlation.risk_score, existing["highest_risk_score"]),
                    scan_id=scan_id,
                )

    def get_all(self) -> list[RegistryEntry]:
        """All exposed devices ever seen, newest first."""
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT id, mac_prefix, last_ip, hostname, device_type,
                       manufacturer, exposed_ports, highest_risk_score,
                       exposure_count, first_exposed, last_exposed,
                       is_new, resolved
                FROM exposed_device_registry
                ORDER BY last_exposed DESC
            """).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_new(self) -> list[RegistryEntry]:
        """Devices flagged as new since last viewed."""
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT id, mac_prefix, last_ip, hostname, device_type,
                       manufacturer, exposed_ports, highest_risk_score,
                       exposure_count, first_exposed, last_exposed,
                       is_new, resolved
                FROM exposed_device_registry
                WHERE is_new = 1
                ORDER BY last_exposed DESC
            """).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_changelog(self, mac_prefix: str = None, limit: int = 50) -> list[ChangelogEntry]:
        """
        Returns the change log for a specific device,
        or the full log if mac_prefix is None.
        """
        with sqlite3.connect(DB_PATH) as conn:
            if mac_prefix:
                rows = conn.execute("""
                    SELECT mac_prefix, event, detail, risk_score, recorded_at
                    FROM registry_changelog
                    WHERE mac_prefix = ?
                    ORDER BY recorded_at DESC LIMIT ?
                """, (mac_prefix, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT mac_prefix, event, detail, risk_score, recorded_at
                    FROM registry_changelog
                    ORDER BY recorded_at DESC LIMIT ?
                """, (limit,)).fetchall()

        return [ChangelogEntry(
            mac_prefix=r[0],
            event=r[1],
            detail=r[2],
            risk_score=r[3],
            recorded_at=datetime.fromisoformat(r[4]),
        ) for r in rows]

    def stats(self) -> dict:
        """Aggregate stats for the dashboard registry panel."""
        with sqlite3.connect(DB_PATH) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM exposed_device_registry"
            ).fetchone()[0]

            new_count = conn.execute(
                "SELECT COUNT(*) FROM exposed_device_registry WHERE is_new = 1"
            ).fetchone()[0]

            resolved = conn.execute(
                "SELECT COUNT(*) FROM exposed_device_registry WHERE resolved = 1"
            ).fetchone()[0]

            highest_risk = conn.execute(
                "SELECT MAX(highest_risk_score) FROM exposed_device_registry"
            ).fetchone()[0] or 0

            most_exposed = conn.execute("""
                SELECT mac_prefix, manufacturer, device_type, exposure_count
                FROM exposed_device_registry
                ORDER BY exposure_count DESC LIMIT 1
            """).fetchone()

        return {
            "total_exposed":      total,
            "new_since_last_view": new_count,
            "resolved":           resolved,
            "highest_risk_score": highest_risk,
            "most_exposed_device": {
                "mac_prefix":     most_exposed[0] if most_exposed else None,
                "manufacturer":   most_exposed[1] if most_exposed else None,
                "device_type":    most_exposed[2] if most_exposed else None,
                "exposure_count": most_exposed[3] if most_exposed else 0,
            },
        }

  

    def mark_all_viewed(self):
        """Clear the is_new flag — called when user opens the registry panel."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE exposed_device_registry SET is_new = 0")
            conn.commit()

    def mark_resolved(self, mac_prefix: str):
        """User has fixed this exposure — mark as resolved."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                UPDATE exposed_device_registry
                SET resolved = 1, is_new = 0
                WHERE mac_prefix = ?
            """, (mac_prefix,))
            conn.commit()
        self._log(
            mac_prefix=mac_prefix,
            scan_id=0,
            event="resolved",
            detail="User marked device as resolved.",
            risk_score=0,
        )
        logger.info(f"Device {mac_prefix} marked as resolved.")

    # ── Internal DB helpers ────────────────────────────────

    def _get_by_mac(self, mac_prefix: str) -> Optional[dict]:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("""
                SELECT mac_prefix, last_ip, exposed_ports,
                       highest_risk_score, exposure_count
                FROM exposed_device_registry
                WHERE mac_prefix = ?
            """, (mac_prefix,)).fetchone()

        if not row:
            return None
        return {
            "mac_prefix":          row[0],
            "last_ip":             row[1],
            "exposed_ports":       json.loads(row[2]),
            "highest_risk_score":  row[3],
            "exposure_count":      row[4],
        }

    def _insert(self, mac_prefix, ip, hostname, device_type,
                manufacturer, ports, risk_score, scan_id):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO exposed_device_registry
                (mac_prefix, last_ip, hostname, device_type, manufacturer,
                 exposed_ports, highest_risk_score, exposure_count,
                 last_scan_id, is_new)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1)
            """, (
                mac_prefix, ip, hostname, device_type, manufacturer,
                json.dumps(ports), risk_score, scan_id,
            ))
            conn.commit()

    def _update(self, mac_prefix, ip, hostname, ports, risk_score, scan_id):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                UPDATE exposed_device_registry SET
                    last_ip            = ?,
                    hostname           = ?,
                    exposed_ports      = ?,
                    highest_risk_score = ?,
                    exposure_count     = exposure_count + 1,
                    last_exposed       = datetime('now'),
                    last_scan_id       = ?,
                    is_new             = 1
                WHERE mac_prefix = ?
            """, (ip, hostname, json.dumps(ports), risk_score, scan_id, mac_prefix))
            conn.commit()

    def _log(self, mac_prefix, scan_id, event, detail, risk_score):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO registry_changelog
                (mac_prefix, scan_id, event, detail, risk_score)
                VALUES (?, ?, ?, ?, ?)
            """, (mac_prefix, scan_id, event, detail, risk_score))
            conn.commit()

    def _row_to_entry(self, row: tuple) -> RegistryEntry:
        return RegistryEntry(
            id=row[0],
            mac_prefix=row[1],
            last_ip=row[2],
            hostname=row[3] or "",
            device_type=row[4],
            manufacturer=row[5],
            exposed_ports=json.loads(row[6]),
            highest_risk_score=row[7],
            exposure_count=row[8],
            first_exposed=datetime.fromisoformat(row[9]),
            last_exposed=datetime.fromisoformat(row[10]),
            is_new=bool(row[11]),
            resolved=bool(row[12]),
        )