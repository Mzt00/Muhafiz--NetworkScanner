"""
plugins/example_plugin.py
Example plugin — Reolink Camera on port 9000.
Use this as a template for writing your own plugins.

Steps to create your own plugin:
1. Copy this file and rename it e.g. my_device_plugin.py
2. Change the class name, metadata, and fingerprint logic
3. Drop it in the plugins/ folder
4. Muhafiz will auto-discover and load it on next startup
"""

import logging
from typing import Optional

from plugins.base import BasePlugin, DeviceMatch
from core.models import ScanResult, ExposureFinding

logger = logging.getLogger(__name__)


class ReoLinkPlugin(BasePlugin):

    # ── Plugin metadata ────────────────────────────────────
    name        = "Reolink Camera Plugin"
    version     = "0.1.0"
    author      = "Muhafiz Community"
    description = "Identifies Reolink IP cameras on port 9000 and RTSP port 554"

    # ── Fingerprint method ─────────────────────────────────

    def fingerprint(self, port: int, banner: str) -> Optional[DeviceMatch]:
        """
        Identify a Reolink camera from its port and banner.
        Returns a DeviceMatch if recognised, None otherwise.
        """
        banner_lower = banner.lower()

        # Reolink control port 9000
        if port == 9000 and any(s in banner_lower for s in ["reolink", "reo-"]):
            return DeviceMatch(
                device_type="ip_camera",
                manufacturer="Reolink",
                risk_base=8,
                confidence=0.95,
                notes="Reolink control port 9000 — matched banner",
            )

        # Reolink RTSP port 554
        if port == 554 and "reolink" in banner_lower:
            return DeviceMatch(
                device_type="ip_camera",
                manufacturer="Reolink",
                risk_base=8,
                confidence=0.90,
                notes="Reolink RTSP stream on port 554",
            )

        # Reolink web interface port 80
        if port == 80 and any(s in banner_lower for s in ["reolink", "reo-link"]):
            return DeviceMatch(
                device_type="ip_camera",
                manufacturer="Reolink",
                risk_base=7,
                confidence=0.85,
                notes="Reolink web interface on port 80",
            )

        return None

    # ── Optional: real-time alert on critical finding ──────

    def on_critical_found(self, finding: ExposureFinding) -> None:
        """
        Called when a critical correlation is found.
        This example just logs it — replace with your own
        alert logic e.g. push notification, Slack, SMS.
        """
        if finding.device.ports:
            op = finding.device.ports[0]
            if op.manufacturer == "Reolink":
                logger.warning(
                    f"[ReoLinkPlugin] ALERT: Reolink camera at "
                    f"{finding.device.ip} is exposed on external port "
                    f"{finding.mapping.external_port} — risk {finding.risk_score}/10"
                )

    # ── Optional: post-scan summary ────────────────────────

    def on_scan_complete(self, result: ScanResult) -> None:
        """
        Called after the full scan completes.
        This example counts how many Reolink cameras were found.
        """
        reolink_devices = [
            d for d in result.devices
            if any(p.manufacturer == "Reolink" for p in d.ports)
        ]
        if reolink_devices:
            logger.info(
                f"[ReoLinkPlugin] Found {len(reolink_devices)} "
                f"Reolink camera(s) on the network."
            )