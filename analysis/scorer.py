"""
scorer.py
Risk Scoring Analysis Layer
Assigns a risk score from 1-10 to each device/finding
based on device type, external exposure, and known CVEs.
"""

import logging

logger = logging.getLogger(__name__)



# How sensitive is this device if exposed to the internet

BASE_SCORES: dict[str, int] = {
    "ip_camera":     9,
    "dvr":           9,
    "ptz_camera":    10,
    "nas":           8,
    "media_server":  7,
    "router":        8,
    "smart_plug":    5,
    "smart_hub":     6,
    "printer":       4,
    "voip_phone":    6,
    "gaming_console":3,
    "phone":         2,
    "laptop":        3,
    "unknown":       5,   #unknown device gets a medium score assume the worst
}


class RiskScorer:

    def score(
        self,
        device_type: str,
        shodan_match: bool = False,
        cves: list[str] = None,
        port: int = None,
    ) -> int:
        """
        Calculate a risk score from 1-10 for a device/finding.

        Args:
            device_type:  e.g. "ip_camera", "printer", "nas"
            shodan_match: True if this port appears in Shodan results
            cves:         list of CVE IDs Shodan flagged on this port
            port:         port number (used for high-risk port bonus)

        Returns:
            int between 1 and 10
        """
        cves = cves or []

        # Start with base score for this device type
        score = BASE_SCORES.get(device_type, BASE_SCORES["unknown"])

        # +2 if the port is externally visible on Shodan
        if shodan_match:
            score += 2
            logger.debug(f"  +2 Shodan match")

        # +1 per CVE, up to +3 maximum
        if cves:
            cve_bonus = min(len(cves), 3)
            score += cve_bonus
            logger.debug(f"  +{cve_bonus} CVEs ({len(cves)} found)")

        # +1 if it's a known high-risk port
        if port and self._is_high_risk_port(port):
            score += 1
            logger.debug(f"  +1 high-risk port {port}")

        # Cap between 1 and 10
        final = max(1, min(score, 10))
        logger.debug(f"  Final score: {final}/10 for {device_type}")
        return final



    def _is_high_risk_port(self, port: int) -> bool:
        """
        Returns True if the port is commonly associated with
        serious exposure risks when open to the internet.
        """
        HIGH_RISK_PORTS = {
            21,    # FTP
            23,    # Telnet
            445,   # SMB (WannaCry etc.)
            554,   # RTSP (camera streams)
            3389,  # RDP (remote desktop)
            5900,  # VNC
            8000,  # Hikvision DVR web panel
            8080,  # Alternative HTTP (often unsecured)
            9000,  # Various device admin panels
            9999,  # TP-Link smart plug control
        }
        return port in HIGH_RISK_PORTS


    def score_all(self, correlations: list) -> list:
       # Re-score a list of CriticalCorrelation objects.
    
        for c in correlations:
            c.risk_score = self.score(
                device_type=c.device.ports[0].device_type if c.device.ports else "unknown",
                shodan_match=True,
                cves=c.exposed_port.cves,
                port=c.exposed_port.port,
            )
        return sorted(correlations, key=lambda c: c.risk_score, reverse=True)


    @staticmethod
    def label(score: int) -> str:
        """Convert a numeric score to a severity label."""
        if score >= 9:
            return "CRITICAL"
        elif score >= 7:
            return "HIGH"
        elif score >= 5:
            return "MEDIUM"
        else:
            return "LOW"