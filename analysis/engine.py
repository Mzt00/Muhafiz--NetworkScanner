"""
engine.py
The Logic Engine — Analysis & Correlation Layer
Compares internal devices against Shodan-exposed ports to produce
CriticalCorrelation findings. Runs real UPnP scan first, then
falls back to device-type heuristics if UPnP scan yields nothing.
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
from analysis.upnp import UPnPScanner

logger = logging.getLogger(__name__)


class LogicEngine:

    def __init__(self):
        self.scorer = RiskScorer()
        self.upnp   = UPnPScanner()


    def analyse(self, result: ScanResult) -> ScanResult:
        """
        Takes a raw ScanResult from core.run_scan() and:
        1. Runs real UPnP scan against the router IGD
        2. Falls back to heuristic UPnP detection if IGD not found
        3. Correlates internal devices with Shodan exposed ports
        4. Scores and sorts all findings
        5. Returns the enriched ScanResult
        """
        logger.info("=" * 50)
        logger.info("Logic Engine starting analysis...")

        exposed_port_nums = {ep.port for ep in result.exposed_ports}

        logger.info("Running UPnP IGD scan...")
        real_leaks = self.upnp.scan(exposed_port_nums)


        # If IGD returned nothing (UPnP disabled on router or
        # router didn't respond), still flag likely leaks
        # based on device type + Shodan match
        if real_leaks:
            result.upnp_leaks = real_leaks
            logger.info(f"UPnP IGD scan found {len(real_leaks)} confirmed leak(s)")
        else:
            logger.info("No IGD response — running heuristic UPnP leak detection...")
            result.upnp_leaks = self._detect_upnp_leaks_heuristic(
                result.devices,
                result.exposed_ports
            )
            if result.upnp_leaks:
                logger.warning(
                    f"Heuristic found {len(result.upnp_leaks)} likely UPnP leak(s) "
                    f"— router IGD not accessible to confirm"
                )

        logger.info("Correlating internal devices with Shodan results...")
        result.correlations = self._correlate(
            result.devices,
            result.exposed_ports
        )

        logger.info("=" * 50)
        logger.info(
            f"Analysis complete:\n"
            f"  Devices scanned:       {len(result.devices)}\n"
            f"  WAN ports exposed:     {len(result.exposed_ports)}\n"
            f"  Critical correlations: {len(result.correlations)}\n"
            f"  UPnP leaks:            {len(result.upnp_leaks)}"
        )
        logger.info("=" * 50)

        return result

    def _correlate(
        self,
        devices: list[Device],
        exposed_ports: list[ExposedPort],
    ) -> list[CriticalCorrelation]:
        """
        For every open port on every internal device, check if the
        same port number appears in the Shodan exposed ports list.
        If it does — that device is reachable from the internet.
        """
        correlations = []
        exposed_map  = {ep.port: ep for ep in exposed_ports}

        for device in devices:
            for open_port in device.ports:
                if open_port.port not in exposed_map:
                    continue

                exposed = exposed_map[open_port.port]
                score   = self.scorer.score(
                    device_type=open_port.device_type,
                    shodan_match=True,
                    cves=exposed.cves,
                    port=open_port.port,
                )

                correlation = CriticalCorrelation(
                    device=device,
                    exposed_port=exposed,
                    risk_score=score,
                    reason=self._build_reason(device, open_port, exposed),
                )
                correlations.append(correlation)

                logger.warning(
                    f"CRITICAL: {device.ip} port {open_port.port} "
                    f"({open_port.device_type} / {open_port.manufacturer}) "
                    f"is exposed on WAN — risk score {score}/10 "
                    f"[{self.scorer.label(score)}]"
                )

        # Sort highest risk first
        correlations.sort(key=lambda c: c.risk_score, reverse=True)

        if not correlations:
            logger.info("No critical correlations found network looks clean.")

        return correlations

    def _detect_upnp_leaks_heuristic(
        self,
        devices: list[Device],
        exposed_ports: list[ExposedPort],
    ) -> list[UPnPLeak]:
        """
        Fallback when the router IGD is not accessible.
        Flags devices that are both:
          - A UPnP-prone device type (cameras, NAS, DVR etc.)
          - Have a port that also appears in Shodan results
        These are likely but not confirmed UPnP leaks.
        """
        UPNP_PRONE = {
            "ip_camera", "dvr", "nas", "media_server",
            "smart_plug", "smart_hub", "voip_phone", "router"
        }
        exposed_port_nums = {ep.port for ep in exposed_ports}
        leaks = []

        for device in devices:
            for open_port in device.ports:
                if (
                    open_port.device_type in UPNP_PRONE
                    and open_port.port in exposed_port_nums
                ):
                    leak = UPnPLeak(
                        internal_ip=device.ip,
                        internal_port=open_port.port,
                        external_port=open_port.port,
                        protocol=open_port.protocol,
                        description=(
                            f"{open_port.manufacturer} {open_port.device_type} "
                            f"— heuristic: likely UPnP auto-mapping "
                            f"(IGD not accessible to confirm)"
                        ),
                        lease_duration=0,
                    )
                    leaks.append(leak)
                    logger.warning(
                        f"LIKELY UPnP LEAK: {device.ip}:{open_port.port} "
                        f"({open_port.device_type}) — port visible on Shodan "
                        f"and device type is UPnP-prone"
                    )

        return leaks

    def _build_reason(self, device, open_port, exposed) -> str:
        """
        Builds a plain-English explanation shown in the dashboard
        alert and the PDF report.
        """
        cve_note = ""
        if exposed.cves:
            cve_note = (
                f" Shodan has flagged the following CVEs on this port: "
                f"{', '.join(exposed.cves[:3])}."
            )

        last_seen = ""
        if exposed.last_seen:
            last_seen = f" Last seen by Shodan: {exposed.last_seen.strftime('%Y-%m-%d')}."

        return (
            f"{open_port.manufacturer} {open_port.device_type} at {device.ip} "
            f"has port {open_port.port}/{open_port.protocol} "
            f"({open_port.service}) open internally — "
            f"this same port is indexed on internet on your public IP, "
            f"meaning it is likely publicly reachable."
            f"{cve_note}"
            f"{last_seen} "
            f"To fix: disable UPnP on your router, or remove the "
            f"port forwarding rule for port {open_port.port}."
        )


    def rescore_all(self, result: ScanResult) -> ScanResult:
        """
        Re-run risk scoring across all correlations.
        Useful after a fingerprint database update changes
        device type assignments.
        """
        for c in result.correlations:
            dtype = c.device.ports[0].device_type if c.device.ports else "unknown"
            c.risk_score = self.scorer.score(
                device_type=dtype,
                shodan_match=True,
                cves=c.exposed_port.cves,
                port=c.exposed_port.port,
            )
        result.correlations.sort(key=lambda c: c.risk_score, reverse=True)
        return result