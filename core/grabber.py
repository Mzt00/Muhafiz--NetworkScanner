"""
grabber.py
The Banner Grabber
Connects to each open port on a discovered device and reads
the raw response banner to identify the manufacturer and device type.
"""

import socket
import json
import logging
import re
from pathlib import Path
from typing import Optional

from core.models import Device, OpenPort

logger = logging.getLogger(__name__)

BANNER_TIMEOUT = 3       # seconds to wait for a banner response
BANNER_MAX_BYTES = 512   # max bytes to read from each port
FINGERPRINTS_PATH = Path("analysis/fingerprints.json")


class BannerGrabber:

    def __init__(self):
        self.fingerprints = self._load_fingerprints()


    def _load_fingerprints(self) -> list[dict]:
        """Load device signatures from fingerprints.json."""
        if not FINGERPRINTS_PATH.exists():
            logger.warning("fingerprints.json not found — device identification will be limited.")
            return []
        try:
            data = json.loads(FINGERPRINTS_PATH.read_text())
            sigs = data.get("signatures", [])
            logger.info(f"Loaded {len(sigs)} fingerprint signature(s)")
            return sigs
        except Exception as e:
            logger.error(f"Failed to load fingerprints.json: {e}")
            return []


    def _grab_banner(self, ip: str, port: int) -> str:
        """
        Open a TCP connection to ip:port and read the first
        BANNER_MAX_BYTES bytes of the response.
        Returns empty string if connection fails or times out.
        """
        try:
            with socket.create_connection((ip, port), timeout=BANNER_TIMEOUT) as sock:
                # Send a generic HTTP requestmany devices respond to this
                # even if they are not web servers
                sock.sendall(b"GET / HTTP/1.0\r\nHost: muhafiz\r\n\r\n")
                banner = sock.recv(BANNER_MAX_BYTES).decode("utf-8", errors="ignore")
                logger.debug(f"  Banner from {ip}:{port} — {repr(banner[:80])}")
                return banner.strip()
        except (socket.timeout, ConnectionRefusedError, OSError):
            return ""


    def _fingerprint(self, port: int, banner: str) -> tuple[str, str]:
        """
        Compare a banner against all loaded signatures.
        Returns (device_type, manufacturer) tuple.
        Falls back to ("unknown", "unknown") if no match found.
        """
        banner_lower = banner.lower()

        for sig in self.fingerprints:
            sig_port = sig.get("port")
            sig_banner = sig.get("banner_contains", "").lower()

            # Port must match AND banner must contain the signature string
            if sig_port == port and sig_banner and sig_banner in banner_lower:
                logger.debug(
                    f"  Fingerprint match: {sig.get('manufacturer')} "
                    f"{sig.get('device_type')} on port {port}"
                )
                return sig.get("device_type", "unknown"), sig.get("manufacturer", "unknown")

        return "unknown", "unknown"


   

    def _sanitize_banner(self, banner: str) -> str:
        """Remove IP addresses from a banner before storing."""
        return re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "[ip]", banner)


    def enrich_device(self, device: Device) -> Device:
        """
        For each open port on a Device, grab the banner and
        run fingerprint matching to fill in device_type and manufacturer.
        Returns the same Device object with enriched OpenPort data.
        """
        logger.info(f"Grabbing banners for {device.ip} ({len(device.ports)} port(s))...")

        enriched_ports = []
        for open_port in device.ports:
            banner = self._grab_banner(device.ip, open_port.port)
            device_type, manufacturer = self._fingerprint(open_port.port, banner)

            enriched_port = OpenPort(
                port=open_port.port,
                protocol=open_port.protocol,
                service=open_port.service,
                banner=self._sanitize_banner(banner) or open_port.banner,
                device_type=device_type,
                manufacturer=manufacturer,
            )
            enriched_ports.append(enriched_port)

        device.ports = enriched_ports
        return device

    def enrich_all(self, devices: list[Device]) -> list[Device]:
        """
        Run banner grabbing and fingerprinting across all
        discovered devices Returns enriched Device list
        """
        logger.info(f"Banner Grabber starting on {len(devices)} device(s)...")
        enriched = [self.enrich_device(device) for device in devices]
        logger.info("Banner Grabber complete.")
        return enriched