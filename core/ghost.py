"""
ghost.py
Module A - The Ghost
Queries Censys for all indexed services on the user's public WAN IP.
Uses the censys Python SDK (pip install censys).

Credentials required in .env:
    CENSYS_API_ID=your_organization_id      (short string e.g. DjiyRVDb)
    CENSYS_API_SECRET=your_pat_token        (long string starting with censys_)

Get credentials at: accounts.censys.io/settings/personal-access-tokens
  - CENSYS_API_ID     = the Token ID shown in the token list (short string)
  - CENSYS_API_SECRET = the full PAT value copied when the token was created
"""

import os
import socket
import logging
from datetime import datetime
from typing import Optional

import requests
from dotenv import load_dotenv
from censys.search import CensysHosts
from censys.common.exceptions import (
    CensysException,
    CensysUnauthorizedException,
    CensysRateLimitExceededException,
)

from core.models import ExposedPort

load_dotenv()
logger = logging.getLogger(__name__)


class GhostScanner:

    def __init__(self):
        api_id     = os.getenv("CENSYS_API_ID")
        api_secret = os.getenv("CENSYS_API_SECRET")

        if not api_id or not api_secret:
            raise ValueError(
                "CENSYS_API_ID and CENSYS_API_SECRET not found in .env.\n"
                "  CENSYS_API_ID     = Token ID (short string e.g. DjiyRVDb)\n"
                "  CENSYS_API_SECRET = Full PAT token (starts with censys_)\n"
                "Get both at: accounts.censys.io/settings/personal-access-tokens"
            )

        self.hosts = CensysHosts(api_id=api_id, api_secret=api_secret)
        logger.info("GhostScanner initialised — Censys SDK ready.")

    # ── Check network connectivity ─────────────────────────

    def is_connected(self) -> bool:
        """
        Check if the machine has an active internet connection.
        Attempts to open a socket to Google DNS (8.8.8.8:53).
        Returns True if connected, False otherwise.
        """
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
        """Detect the user's current public IP address."""
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
        Query Censys for all indexed services on the WAN IP.
        Returns a list of ExposedPort objects.
        Returns empty list gracefully on any API error.

        Censys view() response:
        {
          'ip': '1.2.3.4',
          'services': [
            {
              'port': 80,
              'service_name': 'HTTP',
              'transport_protocol': 'TCP',
              'banner': '...',
              'observed_at': '2024-01-01T00:00:00.000Z',
            }
          ]
        }
        """
        if not wan_ip:
            wan_ip = self.get_wan_ip()

        if not self.is_connected():
            logger.warning("No internet connection — skipping Censys scan.")
            return []

        logger.info(f"Querying Censys for {wan_ip}...")

        try:
            host = self.hosts.view(wan_ip)

        except CensysUnauthorizedException:
            logger.error(
                "Censys credentials invalid. "
                "Check CENSYS_API_ID and CENSYS_API_SECRET in .env.\n"
                "  CENSYS_API_ID     = Token ID (short string e.g. DjiyRVDb)\n"
                "  CENSYS_API_SECRET = Full PAT value (starts with censys_)"
            )
            return []

        except CensysRateLimitExceededException:
            logger.warning("Censys rate limit reached — skipping WAN scan.")
            return []

        except CensysException as e:
            error_str = str(e).lower()
            if "404" in error_str or "not found" in error_str:
                logger.info(f"Censys has no data for {wan_ip} — your IP is clean.")
                return []
            logger.warning(f"Censys API error: {e} — continuing with LAN-only scan.")
            return []

        except Exception as e:
            logger.warning(f"Unexpected error querying Censys: {e}")
            return []

        # ── Parse services ─────────────────────────────────
        services = host.get("services", [])
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

    # ── Helpers ────────────────────────────────────────────

    def _extract_cves(self, service: dict) -> list[str]:
        """
        Extract CVE IDs from a Censys service entry.
        Free tier returns empty list — CVE data requires paid plan.
        Handles both list [{'cve_id': 'CVE-...'}] and
        dict {'CVE-...': {}} formats defensively.
        """
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
        """
        Parse Censys RFC3339 timestamp into a datetime object.
        Censys format examples:
          2024-01-01T00:00:00.000Z
          2024-01-01T00:00:00.000000000Z
        Strategy: strip timezone, strip sub-seconds, parse clean.
        """
        if not ts:
            return None
        # Strip timezone suffix and sub-second precision
        ts = ts.rstrip("Z").split("+")[0].split(".")[0]
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            try:
                return datetime.strptime(ts, "%Y-%m-%dT%H:%M")
            except ValueError:
                return None