"""
engine.py
The Logic Engine — Analysis & Correlation Layer
Compares internal devices against Shodan-exposed ports to produce
CriticalCorrelation findings and detect UPnP leaks.
"""

import logging
from core.models import (
    ScanResult,
    Device,
    ExposedPort,
    CriticalCorrelation,
    UPnPLeak,
)
from analysis.scorer import RiskScorer

logger = logging.getLogger(__name__)


class LogicEngine:

    def __init__(self):
        self.scorer = RiskScorer()

   

    def analyse(self, result: ScanResult) -> ScanResult:
        """
        Takes a raw ScanResult from core.run_scan() and:
        1. Correlates internal devices with Shodan exposed ports
        2. Detects UPnP leaks
        3. Scores each finding
        4. Attaches correlations and leaks back to the ScanResult

        Returns the same ScanResult with correlations and upnp_leaks filled in.
        """
        logger.info("Logic Engine starting analysis...")

        result.correlations = self._correlate(result.devices, result.exposed_ports)
        result.upnp_leaks   = self._detect_upnp_leaks(result.devices, result.exposed_ports)

        logger.info(
            f"Analysis complete — "
            f"{len(result.correlations)} critical correlation(s), "
            f"{len(result.upnp_leaks)} UPnP leak(s)"
        )

        return result


    def _correlate(
        self,
        devices: list[Device],
        exposed_ports: list[ExposedPort],
    ) -> list[CriticalCorrelation]:
        """
        For every open port on every internal device check if the
        same port number appears in the Shodan exposed ports list.
        If it does  that device is reachable from the internet.
        """
        correlations = []
        exposed_map = {ep.port: ep for ep in exposed_ports}

        for device in devices:
            for open_port in device.ports:
                if open_port.port in exposed_map:
                    exposed = exposed_map[open_port.port]

                    score = self.scorer.score(
                        device_type=open_port.device_type,
                        shodan_match=True,
                        cves=exposed.cves,
                    )

                    reason = self._build_reason(device, open_port, exposed)

                    correlation = CriticalCorrelation(
                        device=device,
                        exposed_port=exposed,
                        risk_score=score,
                        reason=reason,
                    )
                    correlations.append(correlation)

                    logger.warning(
                        f"CRITICAL: {device.ip} port {open_port.port} "
                        f"({open_port.device_type}) is exposed on WAN — "
                        f"risk score {score}/10"
                    )

        # Sort highest risk first
        correlations.sort(key=lambda c: c.risk_score, reverse=True)
        return correlations

    def _detect_upnp_leaks(
        self,
        devices: list[Device],
        exposed_ports: list[ExposedPort],
    ) -> list[UPnPLeak]:
        """
        Check for devices that are likely using UPnP to punch holes
        in the router. Identified by cross-referencing device ports
        with Shodan results and flagging known UPnP-prone device types.
        """
        UPnP_PRONE = {"ip_camera", "nas", "media_server", "smart_plug", "dvr"}
        exposed_port_nums = {ep.port for ep in exposed_ports}
        leaks = []

        for device in devices:
            for open_port in device.ports:
                if (
                    open_port.device_type in UPnP_PRONE
                    and open_port.port in exposed_port_nums
                ):
                    leak = UPnPLeak(
                        internal_ip=device.ip,
                        internal_port=open_port.port,
                        external_port=open_port.port,
                        protocol=open_port.protocol,
                        description=(
                            f"{open_port.manufacturer} {open_port.device_type} "
                            f"— likely UPnP auto-mapping"
                        ),
                        lease_duration=0,  # assumed permanent until proven otherwise
                    )
                    leaks.append(leak)
                    logger.warning(
                        f"UPnP LEAK: {device.ip}:{open_port.port} "
                        f"({open_port.device_type}) appears to have an "
                        f"active UPnP port mapping"
                    )

        return leaks

    def _build_reason(self, device, open_port, exposed) -> str:
        """
        Build a plain-English explanation of why a finding is critical.
        This is what gets shown to the user in the dashboard and PDF report.
        """
        cve_note = ""
        if exposed.cves:
            cve_note = f" Known CVEs: {', '.join(exposed.cves[:3])}."

        return (
            f"{open_port.manufacturer} {open_port.device_type} at {device.ip} "
            f"has port {open_port.port}/{open_port.protocol} ({open_port.service}) "
            f"open internally — this port is also indexed on internet on your public IP, "
            f"meaning it may be reachable from the internet."
            f"{cve_note} "
            f"Disable UPnP on your router or remove the port forwarding rule to fix this."
        )