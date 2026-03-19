"""
ghost.py
Module A - The Ghost
Queries Shodan for all indexed services on the user's public WAN IP.
"""

import os
import socket
import logging
from datetime import datetime
from typing import Optional
 
import shodan
import requests
from dotenv import load_dotenv
 
from core.models import ExposedPort

load_dotenv()
logger = logging.getLogger(__name__)


class GhostScanner:

    def __init__(self):
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            raise ValueError("SHODAN_API_KEY has not been configured in .env")
        self.api = shodan.Shodan(api_key)
    def is_connected(self) -> bool:
        """
        Check if the machine has an active internet connection.
        Attempts to open a socket to Googles DNS (8.8.8.8)
        Returns True if connected
        """
        try:
            socket.setdefaulttimeout(5)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
            logger.info("Device is connected to internet")
            return True
        except (socket.error, OSError):
            logger.warning("Device is NOT connected to the internet")
            return False

    

    def get_wan_ip(self) -> str: #get public WAN IP
        """Detect the user's current public IP address."""
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            ip = response.json()["ip"]
            logger.info(f"WAN IP detected: {ip}")
            return ip
        except Exception as e:
            raise RuntimeError(f"Could not detect WAN IP: {e}")


   
    def scan(self, wan_ip: Optional[str] = None) -> list[ExposedPort]:
        """
        Query Shodan for all indexed services on the WAN IP
        Returns a list of ExposedPort objects
        """
        if not wan_ip:
            wan_ip = self.get_wan_ip()

        logger.info(f"Querying Shodan for {wan_ip}...")

        try:
            host = self.api.host(wan_ip)
        except shodan.APIError as e:
            if "No information available" in str(e):
                logger.info(f"Shodan has no data for {wan_ip} — your IP is clean.")
                return []
            raise RuntimeError(f"Shodan API error: {e}")

        exposed = []

        for service in host.get("data", []):
            port = ExposedPort(
                port=service.get("port", 0),
                protocol=service.get("transport", "tcp"),
                service=service.get("_shodan", {}).get("module", "unknown"),
                banner=service.get("data", "")[:500],
                cves=self._extract_cves(service),
                last_seen=self._parse_timestamp(service.get("timestamp")),
            )
            exposed.append(port)
            logger.debug(f"  Found: port {port.port}/{port.protocol} — {port.service}")

        logger.info(f"Shodan returned {len(exposed)} exposed port(s) for {wan_ip}")
        return exposed


   #helper functions

    def _extract_cves(self, service: dict) -> list[str]:
        #Pull CVE IDs from a Shodan service entry
        vulns = service.get("vulns", {})
        return list(vulns.keys()) if vulns else []

    def _parse_timestamp(self, ts: Optional[str]) -> Optional[datetime]:
        #Parse Shodan's timestamp string into a datetime object
        if not ts:
            return None
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            try:
                return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                return None