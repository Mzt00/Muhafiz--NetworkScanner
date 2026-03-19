"""
engine.py
The Logic Engine  Analysis & Correlation Layer
"""

import logging
from core.models import ScanResult, Device, ExposedPort, CriticalCorrelation, UPnPLeak
from analysis.scorer import RiskScorer
from analysis.upnp import UPnPScanner

logger = logging.getLogger(__name__)


class LogicEngine:

    def __init__(self):
        self.scorer  = RiskScorer()
        self.upnp    = UPnPScanner()

    def analyse(self, result: ScanResult) -> ScanResult:
        """
        Takes raw ScanResult from core.run_scan() and:
        1. Runs real UPnP scan against the router
        2. Correlates internal devices with Shodan exposed ports
        3. Scores each finding
        Returns the enriched ScanResult.
        """
        logger.info("Logic Engine starting analysis...")

        # Real UPnP scan
        exposed_port_nums = {ep.port for ep in result.exposed_ports}
        result.upnp_leaks = self.upnp.scan(exposed_port_nums)

        # Correlation
        result.correlations = self._correlate(
            result.devices,
            result.exposed_ports
        )

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
        correlations = []
        exposed_map  = {ep.port: ep for ep in exposed_ports}

        for device in devices:
            for open_port in device.ports:
                if open_port.port in exposed_map:
                    exposed = exposed_map[open_port.port]
                    score   = self.scorer.score(
                        device_type=open_port.device_type,
                        shodan_match=True,
                        cves=exposed.cves,
                        port=open_port.port,
                    )
                    correlations.append(CriticalCorrelation(
                        device=device,
                        exposed_port=exposed,
                        risk_score=score,
                        reason=self._build_reason(device, open_port, exposed),
                    ))
                    logger.warning(
                        f"CRITICAL: {device.ip} port {open_port.port} "
                        f"({open_port.device_type}) exposed — risk {score}/10"
                    )

        correlations.sort(key=lambda c: c.risk_score, reverse=True)
        return correlations

    def _build_reason(self, device, open_port, exposed) -> str:
        cve_note = ""
        if exposed.cves:
            cve_note = f" Known CVEs: {', '.join(exposed.cves[:3])}."
        return (
            f"{open_port.manufacturer} {open_port.device_type} at {device.ip} "
            f"has port {open_port.port}/{open_port.protocol} ({open_port.service}) "
            f"open internally — also indexed by Shodan on your public IP."
            f"{cve_note} "
            f"Disable UPnP on your router or remove the port forwarding rule."
        )