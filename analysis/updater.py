"""
updater.py
Fingerprint Auto-Updater  Analysis Layer
Checks the community API for a newer fingerprints.json.
If the API is not reachable, silently uses the local file.
"""

import json
import logging
import os
import socket
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

FINGERPRINTS_PATH = Path("analysis/fingerprints.json")
ETAG_PATH         = Path("analysis/.fingerprints_etag")
UPDATE_ENDPOINT   = os.getenv(
    "MUHAFIZ_UPDATE_ENDPOINT",
    "https://api.muhafiz.dev/v1/fingerprints.json"
)
REQUEST_TIMEOUT   = 5


class FingerprintUpdater:


    def check_and_update(self) -> bool:
        """
        Try to fetch a newer fingerprints.json from the community API.
        If the API is offline, unreachable, or not yet deployed 
        silently continues with the local bundled file.
        Returns True if updated, False otherwise.
        """
        if not self._is_online():
            logger.info("Offline — using local fingerprints.")
            return False

        if not self._api_reachable():
            logger.info("Community API not yet reachable — using local fingerprints.")
            return False

        etag = self._load_etag()

        try:
            headers = {"If-None-Match": etag} if etag else {}
            response = requests.get(
                UPDATE_ENDPOINT,
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 304:
                logger.info("Fingerprints already up to date.")
                return False

            if response.status_code != 200:
                logger.info(f"Update server returned {response.status_code} — using local fingerprints.")
                return False

            new_data = response.json()

            if not self._validate(new_data):
                logger.warning("Downloaded fingerprints failed validation — keeping local version.")
                return False

            new_version   = new_data.get("meta", {}).get("version", "0.0.0")
            local_version = self._local_version()

            if not self._is_newer(new_version, local_version):
                logger.info(f"Local fingerprints v{local_version} already current.")
                return False

            FINGERPRINTS_PATH.write_text(json.dumps(new_data, indent=2))

            new_etag = response.headers.get("ETag", "")
            if new_etag:
                self._save_etag(new_etag)

            logger.info(
                f"Fingerprints updated: v{local_version} → v{new_version} "
                f"({new_data['meta']['total_signatures']} signatures)"
            )
            return True

        except Exception as e:
            logger.info(f"Update check skipped: {e} — using local fingerprints.")
            return False


    def _api_reachable(self) -> bool:
        """
        Quick HEAD request to see if the API server is up.
        Returns False immediately if connection is refused or times out.
        """
        try:
            r = requests.head(UPDATE_ENDPOINT, timeout=3)
            return r.status_code < 500
        except Exception:
            return False


    def _is_online(self) -> bool:
        try:
            socket.setdefaulttimeout(3)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
            return True
        except OSError:
            return False


    def _local_version(self) -> str:
        try:
            data = json.loads(FINGERPRINTS_PATH.read_text())
            return data.get("meta", {}).get("version", "0.0.0")
        except Exception:
            return "0.0.0"

    def _is_newer(self, remote: str, local: str) -> bool:
        try:
            r = tuple(int(x) for x in remote.split("."))
            l = tuple(int(x) for x in local.split("."))
            return r > l
        except ValueError:
            return False


    def _validate(self, data: dict) -> bool:
        if not isinstance(data, dict):
            return False
        if "meta" not in data or "signatures" not in data:
            return False
        if not isinstance(data["signatures"], list) or len(data["signatures"]) == 0:
            return False
        for sig in data["signatures"][:5]:
            if "port" not in sig or "banner_contains" not in sig:
                return False
        return True

    def _load_etag(self) -> Optional[str]:
        if ETAG_PATH.exists():
            return ETAG_PATH.read_text().strip()
        return None

    def _save_etag(self, etag: str) -> None:
        ETAG_PATH.write_text(etag)

    def status(self) -> dict:
        try:
            data = json.loads(FINGERPRINTS_PATH.read_text())
            meta = data.get("meta", {})
            return {
                "version":          meta.get("version", "unknown"),
                "total_signatures": meta.get("total_signatures", 0),
                "updated_at":       meta.get("updated_at", "unknown"),
                "api_live":         self._api_reachable(),
            }
        except Exception:
            return {
                "version":          "unknown",
                "total_signatures": 0,
                "updated_at":       "unknown",
                "api_live":         False,
            }