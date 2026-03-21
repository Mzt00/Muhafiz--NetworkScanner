"""
registry.py
Device Registry tracks every device seen on the LAN
across scans, keyed by MAC prefix.
Updated for new architecture: ExposureFinding + DeviceRiskFinding.
"""

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import ScanResult, ExposureFinding, DeviceRiskFinding

logger = logging.getLogger(__name__)

DB_PATH = Path("muhafiz.db")

@dataclass
class RegistryEntry:
    id:                 int
    mac_prefix:         str
    last_ip:            str
    hostname:           str
    device_type:        str
    manufacturer:       str
    is_camera:          bool
    open_ports:         list[int]
    highest_risk_score: int
    highest_confidence: int
    scan_count:         int
    exposure_count:     int
    first_seen:         datetime
    last_seen:          datetime
    is_new:             bool
    resolved:           bool


@dataclass
class ChangelogEntry:
    mac_prefix:  str
    event:       str
    detail:      str
    risk_score:  int
    confidence:  int
    recorded_at: datetime


class DeviceRegistry:

    def __init__(self):
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_registry (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_prefix          TEXT    NOT NULL UNIQUE,
                    last_ip             TEXT    NOT NULL,
                    hostname            TEXT,
                    device_type         TEXT    NOT NULL DEFAULT 'unknown',
                    manufacturer        TEXT    NOT NULL DEFAULT 'unknown',
                    is_camera           INTEGER NOT NULL DEFAULT 0,
                    open_ports          TEXT    NOT NULL DEFAULT '[]',
                    highest_risk_score  INTEGER NOT NULL DEFAULT 0,
                    highest_confidence  INTEGER NOT NULL DEFAULT 0,
                    scan_count          INTEGER NOT NULL DEFAULT 0,
                    exposure_count      INTEGER NOT NULL DEFAULT 0,
                    first_seen          TEXT    NOT NULL DEFAULT (datetime('now')),
                    last_seen           TEXT    NOT NULL DEFAULT (datetime('now')),
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
                    confidence  INTEGER NOT NULL DEFAULT 0,
                    recorded_at TEXT    NOT NULL DEFAULT (datetime('now'))
                )
            """)
            conn.commit()


    def update(self, result: ScanResult, scan_id: int):
        """
        Update the registry after each scan.
        Processes both ExposureFinding and DeviceRiskFinding.
        ExposureFindings get higher confidence tracked separately.
        """
        # Process exposure findings first (higher confidence)
        for finding in result.exposure_findings:
            self._process_finding(
                device=finding.device,
                risk_score=finding.risk_score,
                confidence=finding.confidence,
                scan_id=scan_id,
                has_mapping=True,
            )

        # Process device findings (internal risk only)
        for finding in result.device_findings:
            if finding.risk_score < 4:
                continue  # skip very low risk devices
            self._process_finding(
                device=finding.device,
                risk_score=finding.risk_score,
                confidence=finding.confidence,
                scan_id=scan_id,
                has_mapping=False,
            )

    def _process_finding(self, device, risk_score, confidence, scan_id, has_mapping):
        mac_prefix  = ":".join(device.mac.split(":")[:3]) if device.mac else "unknown"
        ports       = [p.port for p in device.ports]
        device_type = device.ports[0].device_type if device.ports else "unknown"
        manufacturer = device.ports[0].manufacturer if device.ports else "unknown"
        existing    = self._get_by_mac(mac_prefix)

        if existing is None:
            self._insert(
                mac_prefix=mac_prefix,
                ip=device.ip,
                hostname=device.hostname,
                device_type=device_type,
                manufacturer=manufacturer,
                is_camera=device.is_camera,
                ports=ports,
                risk_score=risk_score,
                confidence=confidence,
                scan_id=scan_id,
                has_mapping=has_mapping,
            )
            event  = "first_seen_exposed" if has_mapping else "first_seen"
            detail = (
                f"First detected — {manufacturer} {device_type} "
                f"{'with router mapping' if has_mapping else 'internal only'} "
                f"on port(s) {ports}"
            )
            self._log(mac_prefix, scan_id, event, detail, risk_score, confidence)
            logger.info(f"NEW device in registry: {mac_prefix} ({device.ip})")

        else:
            existing_ports = set(existing["open_ports"])
            new_ports      = [p for p in ports if p not in existing_ports]
            all_ports      = list(existing_ports | set(ports))

            if new_ports:
                event  = "new_port"
                detail = f"New port(s) detected: {new_ports}"
            elif has_mapping and existing["exposure_count"] == 0:
                event  = "now_exposed"
                detail = f"Device now has active router mapping on port(s) {ports}"
            else:
                event  = "still_present"
                detail = (
                    f"Device still present "
                    f"{'with mapping' if has_mapping else 'internal only'} "
                    f"on port(s) {ports}"
                )

            self._log(mac_prefix, scan_id, event, detail, risk_score, confidence)
            self._update(
                mac_prefix=mac_prefix,
                ip=device.ip,
                hostname=device.hostname,
                is_camera=device.is_camera,
                ports=all_ports,
                risk_score=max(risk_score, existing["highest_risk_score"]),
                confidence=max(confidence, existing["highest_confidence"]),
                scan_id=scan_id,
                has_mapping=has_mapping,
            )

    def get_all(self) -> list[RegistryEntry]:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT id, mac_prefix, last_ip, hostname, device_type,
                       manufacturer, is_camera, open_ports,
                       highest_risk_score, highest_confidence,
                       scan_count, exposure_count,
                       first_seen, last_seen, is_new, resolved
                FROM device_registry
                ORDER BY highest_risk_score DESC, last_seen DESC
            """).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_new(self) -> list[RegistryEntry]:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT id, mac_prefix, last_ip, hostname, device_type,
                       manufacturer, is_camera, open_ports,
                       highest_risk_score, highest_confidence,
                       scan_count, exposure_count,
                       first_seen, last_seen, is_new, resolved
                FROM device_registry
                WHERE is_new = 1
                ORDER BY highest_risk_score DESC
            """).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_exposed(self) -> list[RegistryEntry]:
        """Devices that have had at least one confirmed mapping."""
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("""
                SELECT id, mac_prefix, last_ip, hostname, device_type,
                       manufacturer, is_camera, open_ports,
                       highest_risk_score, highest_confidence,
                       scan_count, exposure_count,
                       first_seen, last_seen, is_new, resolved
                FROM device_registry
                WHERE exposure_count > 0
                ORDER BY highest_risk_score DESC
            """).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_changelog(
        self,
        mac_prefix: str = None,
        limit: int = 50
    ) -> list[ChangelogEntry]:
        with sqlite3.connect(DB_PATH) as conn:
            if mac_prefix:
                rows = conn.execute("""
                    SELECT mac_prefix, event, detail,
                           risk_score, confidence, recorded_at
                    FROM registry_changelog
                    WHERE mac_prefix = ?
                    ORDER BY recorded_at DESC LIMIT ?
                """, (mac_prefix, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT mac_prefix, event, detail,
                           risk_score, confidence, recorded_at
                    FROM registry_changelog
                    ORDER BY recorded_at DESC LIMIT ?
                """, (limit,)).fetchall()

        return [ChangelogEntry(
            mac_prefix=r[0], event=r[1], detail=r[2],
            risk_score=r[3], confidence=r[4],
            recorded_at=datetime.fromisoformat(r[5]),
        ) for r in rows]

    def stats(self) -> dict:
        with sqlite3.connect(DB_PATH) as conn:
            total      = conn.execute("SELECT COUNT(*) FROM device_registry").fetchone()[0]
            new_count  = conn.execute("SELECT COUNT(*) FROM device_registry WHERE is_new = 1").fetchone()[0]
            exposed    = conn.execute("SELECT COUNT(*) FROM device_registry WHERE exposure_count > 0").fetchone()[0]
            resolved   = conn.execute("SELECT COUNT(*) FROM device_registry WHERE resolved = 1").fetchone()[0]
            cameras    = conn.execute("SELECT COUNT(*) FROM device_registry WHERE is_camera = 1").fetchone()[0]
            max_risk   = conn.execute("SELECT MAX(highest_risk_score) FROM device_registry").fetchone()[0] or 0
            confirmed  = conn.execute("SELECT COUNT(*) FROM device_registry WHERE highest_confidence = 100").fetchone()[0]
        return {
            "total":              total,
            "new_since_view":     new_count,
            "ever_exposed":       exposed,
            "resolved":           resolved,
            "cameras":            cameras,
            "highest_risk":       max_risk,
            "confirmed_reachable": confirmed,
        }


    def mark_all_viewed(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE device_registry SET is_new = 0")
            conn.commit()

    def mark_resolved(self, mac_prefix: str):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                UPDATE device_registry
                SET resolved = 1, is_new = 0
                WHERE mac_prefix = ?
            """, (mac_prefix,))
            conn.commit()
        self._log(mac_prefix, 0, "resolved", "User marked as resolved.", 0, 0)
        logger.info(f"Device {mac_prefix} marked as resolved.")

    def _get_by_mac(self, mac_prefix: str) -> Optional[dict]:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("""
                SELECT mac_prefix, last_ip, open_ports,
                       highest_risk_score, highest_confidence,
                       scan_count, exposure_count
                FROM device_registry WHERE mac_prefix = ?
            """, (mac_prefix,)).fetchone()
        if not row:
            return None
        return {
            "mac_prefix":         row[0],
            "last_ip":            row[1],
            "open_ports":         json.loads(row[2]),
            "highest_risk_score": row[3],
            "highest_confidence": row[4],
            "scan_count":         row[5],
            "exposure_count":     row[6],
        }

    def _insert(self, mac_prefix, ip, hostname, device_type, manufacturer,
                is_camera, ports, risk_score, confidence, scan_id, has_mapping):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO device_registry
                (mac_prefix, last_ip, hostname, device_type, manufacturer,
                 is_camera, open_ports, highest_risk_score, highest_confidence,
                 scan_count, exposure_count, last_scan_id, is_new)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1)
            """, (
                mac_prefix, ip, hostname, device_type, manufacturer,
                1 if is_camera else 0,
                json.dumps(ports), risk_score, confidence,
                1 if has_mapping else 0,
                scan_id,
            ))
            conn.commit()

    def _update(self, mac_prefix, ip, hostname, is_camera, ports,
                risk_score, confidence, scan_id, has_mapping):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                UPDATE device_registry SET
                    last_ip            = ?,
                    hostname           = ?,
                    is_camera          = ?,
                    open_ports         = ?,
                    highest_risk_score = ?,
                    highest_confidence = ?,
                    scan_count         = scan_count + 1,
                    exposure_count     = exposure_count + ?,
                    last_seen          = datetime('now'),
                    last_scan_id       = ?,
                    is_new             = 1
                WHERE mac_prefix = ?
            """, (
                ip, hostname,
                1 if is_camera else 0,
                json.dumps(ports),
                risk_score, confidence,
                1 if has_mapping else 0,
                scan_id, mac_prefix,
            ))
            conn.commit()

    def _log(self, mac_prefix, scan_id, event, detail, risk_score, confidence):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO registry_changelog
                (mac_prefix, scan_id, event, detail, risk_score, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (mac_prefix, scan_id, event, detail, risk_score, confidence))
            conn.commit()

    def _row_to_entry(self, row) -> RegistryEntry:
        return RegistryEntry(
            id=row[0], mac_prefix=row[1], last_ip=row[2],
            hostname=row[3] or "", device_type=row[4], manufacturer=row[5],
            is_camera=bool(row[6]),
            open_ports=json.loads(row[7]),
            highest_risk_score=row[8], highest_confidence=row[9],
            scan_count=row[10], exposure_count=row[11],
            first_seen=datetime.fromisoformat(row[12]),
            last_seen=datetime.fromisoformat(row[13]),
            is_new=bool(row[14]), resolved=bool(row[15]),
        )