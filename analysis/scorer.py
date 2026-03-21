"""
scorer.py
Scores devices 1-10 with a confidence percentage.
Score is based on: device type + open ports + mapping confirmation
                   + external verification result.
Confidence reflects how certain we are about the score.
"""

import logging
from core.models import (
    Device,
    PortMapping,
    ExternalVerification,
    OpenPort,
)

logger = logging.getLogger(__name__)
BASE_SCORES: dict[str, int] = {
    "ip_camera":      7,
    "ptz_camera":     7,
    "dvr":            7,
    "nas":            6,
    "router":         6,
    "media_server":   5,
    "voip_phone":     5,
    "smart_hub":      4,
    "smart_plug":     4,
    "printer":        3,
    "gaming_console": 2,
    "phone":          2,
    "laptop":         2,
    "unknown":        4,
}
HIGH_RISK_PORTS: dict[int, tuple[int, str]] = {
    23:   (2, "Telnet open — credentials sent in plaintext"),
    21:   (1, "FTP open — unencrypted file transfer"),
    445:  (3, "SMB open — ransomware vector (WannaCry etc.)"),
    3389: (2, "RDP open — remote desktop brute force risk"),
    5900: (2, "VNC open — unencrypted remote desktop"),
    554:  (1, "RTSP open — camera stream port"),
    8000: (1, "Port 8000 — common DVR/camera web panel"),
    8080: (1, "Port 8080 — often unsecured web interface"),
    9999: (1, "Port 9999 — smart plug control port"),
    5060: (1, "SIP open — VoIP signalling port"),
}


class RiskScorer:

    def score_device(
        self,
        device: Device,
    ) -> tuple[int, int, list[str], list[str]]:
        """
        Score a device that has NO confirmed port mapping.
        These are internal-risk-only findings.

        Returns:
            (score, confidence, reasons, remediation)
            score:      1-10
            confidence: 0-100 — lower because we cannot confirm
                        external exposure without a mapping
        """
        device_type  = self._get_device_type(device)
        open_ports   = [p.port for p in device.ports]
        reasons      = []
        remediation  = []

        # Base score
        score = BASE_SCORES.get(device_type, BASE_SCORES["unknown"])
        reasons.append(
            f"Device type '{device_type}' — base risk {score}/10"
        )

        # Unknown device penalty
        if device_type == "unknown":
            score += 1
            reasons.append("Device type unidentified — elevated uncertainty")

        # ONVIF confirmed camera
        if device.is_camera and device_type not in ("ip_camera", "ptz_camera"):
            score = max(score, 7)
            reasons.append("ONVIF probe confirmed this is an IP camera")

        # High-risk port bonuses
        for port in open_ports:
            if port in HIGH_RISK_PORTS:
                bonus, reason = HIGH_RISK_PORTS[port]
                score += bonus
                reasons.append(reason)

        # Many open ports
        if len(open_ports) > 5:
            score += 1
            reasons.append(
                f"{len(open_ports)} open ports — large attack surface"
            )

        # Cap score
        score = max(1, min(score, 10))

        # Confidence — lower because no mapping confirms external exposure
        # A device is risky internally but we can't confirm it's exposed
        confidence = 30 if score >= 7 else 20
        reasons.append(
            "No active port mapping found — internal risk only"
        )

        # Remediation
        remediation = self._build_remediation(device_type, open_ports, False)

        return score, confidence, reasons, remediation

    def score_exposure(
        self,
        device:        Device,
        mapping:       PortMapping,
        verification:  ExternalVerification = None,
    ) -> tuple[int, int, list[str], list[str]]:
        """
        Score a device that HAS a confirmed port mapping.
        These are exposure findings — far more serious.

        Returns:
            (score, confidence, reasons, remediation)
        """
        device_type = self._get_device_type(device)
        open_ports  = [p.port for p in device.ports]
        reasons     = []
        remediation = []

        # Base score — start higher because mapping is confirmed
        score = BASE_SCORES.get(device_type, BASE_SCORES["unknown"])
        reasons.append(
            f"Device type '{device_type}' — base risk {score}/10"
        )

        # Confirmed mapping bonus — this is real exposure
        score += 2
        reasons.append(
            f"Active port mapping confirmed by router: "
            f"external port {mapping.external_port} → "
            f"internal {mapping.internal_ip}:{mapping.internal_port} "
            f"(source: {mapping.source})"
        )

        # ONVIF confirmed camera
        if device.is_camera:
            score = max(score, 8)
            reasons.append(
                "ONVIF confirmed IP camera — high sensitivity device"
            )

        # High-risk port bonuses
        for port in open_ports:
            if port in HIGH_RISK_PORTS:
                bonus, reason = HIGH_RISK_PORTS[port]
                score += bonus
                reasons.append(reason)

        # External verification result
        confidence = 70  # base confidence with confirmed mapping

        if verification is not None:
            if verification.reachable:
                score += 1
                confidence = 100
                reasons.append(
                    f"External connection CONFIRMED — "
                    f"{self._wan_ip_display(verification.wan_ip)}:"
                    f"{verification.external_port} responded via "
                    f"{verification.protocol.upper()}"
                )
                if verification.banner:
                    reasons.append(
                        f"Response banner: {verification.banner[:80]}"
                    )
            else:
                confidence = 70
                reasons.append(
                    "Port mapping exists but external connection failed — "
                    "possible firewall or CGNAT. Mapping should still be removed."
                )

        # Cap score
        score = max(1, min(score, 10))

        # Remediation
        remediation = self._build_remediation(
            device_type, open_ports, True, mapping
        )

        return score, confidence, reasons, remediation

    @staticmethod
    def label(score: int) -> str:
        if score >= 9:
            return "CRITICAL"
        elif score >= 7:
            return "HIGH"
        elif score >= 5:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def confidence_label(confidence: int) -> str:
        if confidence == 100:
            return "Confirmed"
        elif confidence >= 70:
            return "Likely"
        elif confidence >= 40:
            return "Possible"
        else:
            return "Uncertain"


    def _build_remediation(
        self,
        device_type: str,
        open_ports:  list[int],
        has_mapping: bool,
        mapping:     PortMapping = None,
    ) -> list[str]:
        steps = []

        if has_mapping and mapping:
            steps.append(
                f"Remove the port forwarding rule for external port "
                f"{mapping.external_port} on your router"
            )
            steps.append(
                "Disable UPnP on your router to prevent automatic "
                "port mapping in future"
            )

        if 23 in open_ports:
            steps.append(
                "Disable Telnet on this device — use SSH instead"
            )
        if 21 in open_ports:
            steps.append(
                "Disable FTP. Use SFTP or SCP instead"
            )
        if 554 in open_ports and device_type in ("ip_camera", "ptz_camera", "dvr"):
            steps.append(
                "Restrict RTSP access to local network only in camera settings"
            )
        if 3389 in open_ports:
            steps.append(
                "Disable RDP or restrict it to a VPN — never expose to internet"
            )
        if 445 in open_ports:
            steps.append(
                "Block SMB (port 445) at the router — never expose to internet"
            )
        if device_type in ("ip_camera", "ptz_camera", "dvr"):
            steps.append(
                "Change default credentials on this camera if not already done"
            )
            steps.append(
                "Update camera firmware to latest version"
            )

        if not steps:
            steps.append(
                "Review open ports on this device and disable any unused services"
            )

        return steps

    #helper functions

    def _get_device_type(self, device: Device) -> str:
        """Get the most specific device type from the device's ports."""
        if device.is_camera:
            return "ip_camera"
        for port in device.ports:
            if port.device_type != "unknown":
                return port.device_type
        return "unknown"

    def _wan_ip_display(self, wan_ip: str) -> str:
        """Partially mask WAN IP for display privacy."""
        parts = wan_ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.x.x"
        return wan_ip