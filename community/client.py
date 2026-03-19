"""
client.py

Handles submitting sanitised findings to the community API.
Manages retries, offline queuing, and status polling.
"""

import json
import logging
import os
import socket
import sqlite3
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

from core.models import ContributionPayload

load_dotenv()
logger = logging.getLogger(__name__)

DB_PATH            = Path("muhafiz.db")
CONTRIBUTE_ENDPOINT = os.getenv(
    "MUHAFIZ_CONTRIBUTE_ENDPOINT",
    "https://api.muhafiz.dev/v1/contribute"
)
REQUEST_TIMEOUT    = 10
MAX_RETRIES        = 3


class SubmissionStatus:
    PENDING  = "pending"
    MERGED   = "merged"
    REJECTED = "rejected"
    QUEUED   = "queued"     # offline waiting to be sent
    FAILED   = "failed"


class ContributionClient:

    def __init__(self):
        self._init_db()

    def _init_db(self):
        """Create contributions table if it doesn't exist."""
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


    def submit(self, payload: ContributionPayload) -> dict:
        """
        Submit a sanitised contribution payload to the API.
        If offline  queues locally and returns queued status.
        If API unreachable —queues and retries later.

        Returns dict with uuid and status.
        """
        submission_uuid = str(uuid.uuid4())

        # Save locally first — always
        self._save_local(submission_uuid, payload, SubmissionStatus.QUEUED)

        if not self._is_online():
            logger.info("Offline — contribution queued locally for later submission.")
            return {"uuid": submission_uuid, "status": SubmissionStatus.QUEUED}

        if not self._api_reachable():
            logger.info("API not yet reachable — contribution queued locally.")
            return {"uuid": submission_uuid, "status": SubmissionStatus.QUEUED}

        # Attempt submission
        result = self._post(submission_uuid, payload)
        return result

    def _post(self, submission_uuid: str, payload: ContributionPayload) -> dict:
        """
        POST the payload to the API with retry logic.
        Updates local status based on response.
        """
        data = {
            "uuid":           submission_uuid,
            "port":           payload.port,
            "banner_snippet": payload.banner_snippet,
            "device_type":    payload.device_type,
            "manufacturer":   payload.manufacturer,
            "risk_score":     payload.risk_score,
            "shodan_match":   payload.shodan_match,
            "client_version": payload.client_version,
            "contributed_at": payload.contributed_at.isoformat(),
        }

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = requests.post(
                    CONTRIBUTE_ENDPOINT,
                    json=data,
                    timeout=REQUEST_TIMEOUT,
                )

                if response.status_code == 200:
                    self._update_status(submission_uuid, SubmissionStatus.PENDING)
                    logger.info(f"Contribution submitted successfully — uuid: {submission_uuid}")
                    return {"uuid": submission_uuid, "status": SubmissionStatus.PENDING}

                elif response.status_code == 429:
                    logger.warning("Rate limited by API — queuing for later.")
                    self._update_status(submission_uuid, SubmissionStatus.QUEUED)
                    return {"uuid": submission_uuid, "status": SubmissionStatus.QUEUED}

                elif response.status_code == 422:
                    logger.warning(f"Payload rejected by API validation: {response.text}")
                    self._update_status(submission_uuid, SubmissionStatus.FAILED)
                    return {"uuid": submission_uuid, "status": SubmissionStatus.FAILED}

                else:
                    logger.warning(f"API returned {response.status_code} on attempt {attempt}")

            except requests.exceptions.Timeout:
                logger.warning(f"Request timed out on attempt {attempt}/{MAX_RETRIES}")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error on attempt {attempt}/{MAX_RETRIES}")
            except Exception as e:
                logger.warning(f"Unexpected error on attempt {attempt}: {e}")

        # All retries failed — leave as queued
        logger.warning("All submission attempts failed — contribution remains queued.")
        return {"uuid": submission_uuid, "status": SubmissionStatus.QUEUED}


    def retry_queued(self) -> int:
        """
        Attempt to submit all locally queued contributions.
        Called on startup if online.
        Returns number of successfully submitted items.
        """
        if not self._is_online() or not self._api_reachable():
            return 0

        queued = self._get_queued()
        submitted = 0

        for row in queued:
            sub_uuid, port, banner, dtype, mfr, risk, shodan, contributed_at = row

            payload = ContributionPayload(
                port=port,
                banner_snippet=banner or "",
                device_type=dtype or "unknown",
                manufacturer=mfr or "unknown",
                risk_score=risk or 5,
                shodan_match=bool(shodan),
                client_version="0.4.0",
                contributed_at=datetime.fromisoformat(contributed_at),
            )

            result = self._post(sub_uuid, payload)
            if result["status"] == SubmissionStatus.PENDING:
                submitted += 1

        if submitted:
            logger.info(f"Retried queued contributions — {submitted} submitted.")

        return submitted

    def poll_status(self, submission_uuid: str) -> Optional[str]:
        """
        Poll the API to check if a pending submission has been
        merged or rejected. Updates local status if changed.
        """
        if not self._is_online() or not self._api_reachable():
            return None

        try:
            response = requests.get(
                f"{CONTRIBUTE_ENDPOINT.rsplit('/contribute', 1)[0]}/status/{submission_uuid}",
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                data   = response.json()
                status = data.get("status", SubmissionStatus.PENDING)
                self._update_status(submission_uuid, status)
                return status

        except Exception as e:
            logger.debug(f"Status poll failed for {submission_uuid}: {e}")

        return None

    def poll_all_pending(self):
        """Poll status for all pending submissions."""
        pending = self._get_by_status(SubmissionStatus.PENDING)
        for (sub_uuid,) in pending:
            self.poll_status(sub_uuid)

    def _save_local(self, sub_uuid: str, payload: ContributionPayload, status: str):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT OR IGNORE INTO contributions
                (uuid, port, banner_snippet, device_type, manufacturer,
                 risk_score, shodan_match, status, contributed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sub_uuid,
                payload.port,
                payload.banner_snippet,
                payload.device_type,
                payload.manufacturer,
                payload.risk_score,
                1 if payload.shodan_match else 0,
                status,
                payload.contributed_at.isoformat(),
            ))
            conn.commit()

    def _update_status(self, sub_uuid: str, status: str):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "UPDATE contributions SET status = ?, updated_at = datetime('now') WHERE uuid = ?",
                (status, sub_uuid)
            )
            conn.commit()

    def _get_queued(self) -> list:
        with sqlite3.connect(DB_PATH) as conn:
            return conn.execute("""
                SELECT uuid, port, banner_snippet, device_type,
                       manufacturer, risk_score, shodan_match, contributed_at
                FROM contributions WHERE status = ?
            """, (SubmissionStatus.QUEUED,)).fetchall()

    def _get_by_status(self, status: str) -> list:
        with sqlite3.connect(DB_PATH) as conn:
            return conn.execute(
                "SELECT uuid FROM contributions WHERE status = ?", (status,)
            ).fetchall()

    def _is_online(self) -> bool:
        try:
            socket.setdefaulttimeout(3)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
            return True
        except OSError:
            return False

    def _api_reachable(self) -> bool:
        try:
            r = requests.head(CONTRIBUTE_ENDPOINT, timeout=3)
            return r.status_code < 500
        except Exception:
            return False