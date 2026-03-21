"""
ghost.py

Queries Censys for all indexed services on the user's public WAN IP.
Uses the censys Python library (pip install censys).

Credentials required in .env:
    CENSYS_API_ID=your_api_id
    CENSYS_API_SECRET=your_api_secret

Get your free API credentials at: search.censys.io/account/api
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
                "CENSYS_API_ID and CENSYS_API_SECRET not found in .env. "
                "Get free credentials at search.censys.io/account/api"
            )

        self.hosts = CensysHosts(api_id=api_id, api_secret=api_secret)
        logger.info("GhostScanner initialised with Censys API.")


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


    def scan(self, wan_ip: Optional[str] = None) -> list[ExposedPort]:
        """
        Query Censys for all indexed services on the WAN IP.
        Returns a list of ExposedPort objects.
        Returns empty list gracefully on any API error.
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
                "Censys API credentials invalid or expired. "
                "Check CENSYS_API_ID and CENSYS_API_SECRET in .env."
            )
            return []
        except CensysRateLimitExceededException:
            logger.warning("Censys rate limit reached — skipping WAN scan for now.")
            return []
        except CensysException as e:
            if "404" in str(e) or "not found" in str(e).lower():
                logger.info(f"Censys has no data for {wan_ip} — your IP is clean.")
                return []
            logger.warning(f"Censys API error: {e} — continuing with LAN-only scan.")
            return []
        except Exception as e:
            logger.warning(f"Unexpected error querying Censys: {e}")
            return []

        
        # Censys view() returns:
        # {
        #   'ip': '1.2.3.4',
        #   'services': [
        #     {
        #       'port': 80,
        #       'service_name': 'HTTP',
        #       'transport_protocol': 'TCP',
        #       'banner': '...',
        #       'observed_at': '2024-01-01T00:00:00Z',
        #       'vulns': [{'id': 'CVE-2021-...', ...}]  # enterprise only
        #     }
        #   ]
        # }

        services = host.get("services", [])
        exposed  = []

        for service in services:
            port = ExposedPort(
                port=service.get("port", 0),
                protocol=service.get("transport_protocol", "TCP").lower(),
                service=service.get("service_name", "unknown"),
                banner=service.get("banner", "")[:500],
                cves=self._extract_cves(service),
                last_seen=self._parse_timestamp(service.get("observed_at")),
            )
            exposed.append(port)
            logger.debug(
                f"  Found: port {port.port}/{port.protocol} — {port.service}"
            )

        logger.info(f"Censys returned {len(exposed)} exposed port(s) for {wan_ip}")
        return exposed

  #helper funtions

    def _extract_cves(self, service: dict) -> list[str]:
        """
        Extract CVE IDs from a Censys service entry.
        Censys returns vulns as a list of dicts: [{'id': 'CVE-...'}]
        Unlike Shodan which returns a dict keyed by CVE ID.
        Only available on Enterprise plan — returns [] on free tier.
        """
        vulns = service.get("vulns", [])
        if isinstance(vulns, list):
            return [v.get("id", "") for v in vulns if v.get("id")]
        # Fallback in case format differs
        if isinstance(vulns, dict):
            return list(vulns.keys())
        return []

    def _parse_timestamp(self, ts: Optional[str]) -> Optional[datetime]:
        """
        Parse Censys timestamp string into a datetime object.
        Censys uses RFC3339 format: 2024-01-01T00:00:00.000Z
        """
        if not ts:
            return None
        # Strip trailing Z and handle microseconds
        ts = ts.rstrip("Z").split("+")[0]
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M",
        ):
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        logger.debug(f"Could not parse timestamp: {ts}")
        return None