"""
ghost.py
Module A - The Ghost
Queries Censys REST API directly using Personal Access Token.
No SDK required — works with free tier.

Credentials required in .env:
    CENSYS_API_ID=DjiyRVDb          (Token ID — short string)
    CENSYS_API_SECRET=your_full_pat (Full PAT token)
"""

import os
import socket
import logging
from datetime import datetime
from typing import Optional

import requests
from dotenv import load_dotenv

from core.models import ExposedPort

load_dotenv()
logger = logging.getLogger(__name__)

CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"


class GhostScanner:

    def __init__(self):
        api_id     = os.getenv("CENSYS_API_ID")
        api_secret = os.getenv("CENSYS_API_SECRET")

        if not api_id or not api_secret:
            raise ValueError(
                "CENSYS_API_ID and CENSYS_API_SECRET not found in .env."
            )

        # Censys REST API uses HTTP Basic Auth
        # api_id = username, api_secret = password
        self.auth = (api_id, api_secret)
        logger.info("GhostScanner initialised — Censys REST API ready.")

    # ── Check network connectivity ─────────────────────────

    def is_connected(self) -> bool:
        try:
            socket.setdefaulttimeout(5)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
            logger.info("Network check passed — internet connection detected.")
            return True
        except (socket.error, OSError):
            logger.warning("Network check failed — no internet connection detected.")
            return False

    # ── Get public WAN IP ──────────────────────────────────

    def get_wan_ip(self) -> str:
        if not self.is_connected():
            raise RuntimeError(
                "No internet connection. "
                "Please check your Wi-Fi or network cable and try again."
            )
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            ip = response.json()["ip"]
            logger.info(f"WAN IP detected: {ip}")
            return ip
        except Exception as e:
            raise RuntimeError(f"Could not detect WAN IP: {e}")

    # ── Query Censys ───────────────────────────────────────

    def scan(self, wan_ip: Optional[str] = None) -> list[ExposedPort]:
        """
        Query Censys REST API for all indexed services on the WAN IP.
        Uses HTTP Basic Auth: api_id as username, api_secret as password.
        Returns empty list gracefully on any error.
        """
        if not wan_ip:
            wan_ip = self.get_wan_ip()

        if not self.is_connected():
            logger.warning("No internet connection — skipping Censys scan.")
            return []

        logger.info(f"Querying Censys for {wan_ip}...")

        try:
            response = requests.get(
                CENSYS_HOST_URL.format(ip=wan_ip),
                auth=self.auth,
                timeout=10,
            )

            if response.status_code == 404:
                logger.info(f"Censys has no data for {wan_ip} — your IP is clean.")
                return []

            if response.status_code == 401:
                logger.error(
                    "Censys credentials invalid (401). "
                    "Check CENSYS_API_ID and CENSYS_API_SECRET in .env."
                )
                return []

            if response.status_code == 429:
                logger.warning("Censys rate limit reached — skipping WAN scan.")
                return []

            if response.status_code != 200:
                logger.warning(
                    f"Censys returned HTTP {response.status_code} — "
                    "continuing with LAN-only scan."
                )
                return []

            data     = response.json()
            result   = data.get("result", {})
            services = result.get("services", [])
            exposed  = []

            for service in services:
                ep = ExposedPort(
                    port=service.get("port", 0),
                    protocol=service.get("transport_protocol", "TCP").lower(),
                    service=service.get("service_name", "unknown"),
                    banner=service.get("banner", "")[:500],
                    cves=self._extract_cves(service),
                    last_seen=self._parse_timestamp(service.get("observed_at")),
                )
                exposed.append(ep)
                logger.debug(
                    f"  Found: port {ep.port}/{ep.protocol} — {ep.service}"
                )

            logger.info(
                f"Censys returned {len(exposed)} exposed port(s) for {wan_ip}"
            )
            return exposed

        except requests.exceptions.Timeout:
            logger.warning("Censys request timed out — continuing with LAN-only scan.")
            return []
        except requests.exceptions.ConnectionError:
            logger.warning("Could not reach Censys — continuing with LAN-only scan.")
            return []
        except Exception as e:
            logger.warning(f"Unexpected error querying Censys: {e}")
            return []

    # ── Helpers ────────────────────────────────────────────

    def _extract_cves(self, service: dict) -> list[str]:
        vulns = service.get("vulns", [])
        if isinstance(vulns, list):
            return [
                v.get("cve_id") or v.get("id") or ""
                for v in vulns
                if v.get("cve_id") or v.get("id")
            ]
        if isinstance(vulns, dict):
            return list(vulns.keys())
        return []

    def _parse_timestamp(self, ts: Optional[str]) -> Optional[datetime]:
        if not ts:
            return None
        ts = ts.rstrip("Z").split("+")[0].split(".")[0]
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            try:
                return datetime.strptime(ts, "%Y-%m-%dT%H:%M")
            except ValueError:
                return None