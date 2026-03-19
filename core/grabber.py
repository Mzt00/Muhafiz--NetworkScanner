"""
grabber.py
The Banner Grabber
Connects to each open port, tries multiple probes to extract
a banner, then matches against fingerprints.json to identify
the manufacturer and device type.
"""

import socket
import json
import logging
import re
from pathlib import Path

from core.models import Device, OpenPort

logger = logging.getLogger(__name__)

BANNER_TIMEOUT   = 3
BANNER_MAX_BYTES = 512
FINGERPRINTS_PATH = Path("analysis/fingerprints.json")

# Probes sent to a port to elicit a banner response.
# Tried in order — first non-empty response wins.
PROBES = [
    b"GET / HTTP/1.0\r\nHost: muhafiz\r\n\r\n",                 # HTTP GET
    b"HEAD / HTTP/1.0\r\nHost: muhafiz\r\n\r\n",                # HTTP HEAD
    b"OPTIONS / RTSP/1.0\r\nCSeq: 1\r\n\r\n",                  # RTSP (cameras)
    b"\r\n",                                                      # bare newline (telnet/ftp)
    b"",                                                          # passive — just read
]


class BannerGrabber:

    def __init__(self):
        self.fingerprints = self._load_fingerprints()

    # ── Load fingerprint database ──────────────────────────

    def _load_fingerprints(self) -> list[dict]:
        if not FINGERPRINTS_PATH.exists():
            logger.warning("fingerprints.json not found — device identification limited.")
            return []
        try:
            data = json.loads(FINGERPRINTS_PATH.read_text())
            sigs = data.get("signatures", [])
            logger.info(f"Loaded {len(sigs)} fingerprint signature(s)")
            return sigs
        except Exception as e:
            logger.error(f"Failed to load fingerprints.json: {e}")
            return []

    # ── Grab banner with multiple probes ──────────────────

    def _grab_banner(self, ip: str, port: int) -> str:
        """
        Try multiple probe types against ip:port.
        Returns the first non-empty response, or empty string.
        """
        for probe in PROBES:
            try:
                with socket.create_connection((ip, port), timeout=BANNER_TIMEOUT) as sock:
                    if probe:
                        sock.sendall(probe)
                    banner = sock.recv(BANNER_MAX_BYTES).decode("utf-8", errors="ignore").strip()
                    if banner:
                        logger.debug(f"  Banner [{ip}:{port}] probe={repr(probe[:20])} → {repr(banner[:80])}")
                        return banner
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
        return ""

    # ── Match banner against fingerprint DB ───────────────

    def _fingerprint(self, port: int, banner: str) -> tuple[str, str]:
        """
        Returns (device_type, manufacturer).
        Matches if port matches AND any banner_contains string
        is found in the banner (case-insensitive).
        Falls back to port-only match if banner is empty.
        """
        banner_lower = banner.lower()

        # Pass 1: port + banner match
        for sig in self.fingerprints:
            if sig.get("port") != port:
                continue

            match_strings = sig.get("banner_contains", [])
            if isinstance(match_strings, str):
                match_strings = [match_strings]

            for ms in match_strings:
                if ms and ms.lower() in banner_lower:
                    logger.debug(f"  Fingerprint match: '{ms}' → {sig.get('manufacturer')} {sig.get('device_type')}")
                    return sig.get("device_type", "unknown"), sig.get("manufacturer", "unknown")

        # Pass 2: if banner is empty, return first port-only match
        # so we at least know the likely device type from the port
        if not banner:
            for sig in self.fingerprints:
                if sig.get("port") == port:
                    logger.debug(f"  Port-only match on {port} → {sig.get('manufacturer')} {sig.get('device_type')}")
                    return sig.get("device_type", "unknown"), sig.get("manufacturer", "unknown")

        return "unknown", "unknown"

   

    def _sanitize_banner(self, banner: str) -> str: #remove ip and mac before entering to DB
        return re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "[ip]", banner)

    def enrich_device(self, device: Device) -> Device:
        logger.info(f"Grabbing banners for {device.ip} ({len(device.ports)} port(s))...")
        enriched = []

        for op in device.ports:
            banner       = self._grab_banner(device.ip, op.port)
            dtype, mfr   = self._fingerprint(op.port, banner)

            enriched.append(OpenPort(
                port=op.port,
                protocol=op.protocol,
                service=op.service,
                banner=self._sanitize_banner(banner) or op.banner,
                device_type=dtype,
                manufacturer=mfr,
            ))

        device.ports = enriched
        return device

    def enrich_all(self, devices: list[Device]) -> list[Device]:
        logger.info(f"Banner Grabber starting — {len(devices)} device(s)...")
        result = [self.enrich_device(d) for d in devices]
        logger.info("Banner Grabber complete.")
        return result