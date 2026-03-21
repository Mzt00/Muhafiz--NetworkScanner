"""
engine.py
Logic Engine — Full LAN Architecture
Orchestrates: ONVIF enrichment → Router mapping → Exposure correlation
              → External verification → Risk scoring → Plugin hooks

Layer flow:
  Layer 2: ONVIF enrichment (Device Intelligence)
  Layer 3: UPnP/NAT-PMP mappings (Router Intelligence)
  Layer 4: Exposure correlation (match devices to mappings)
  Layer 5: External verification (confirm reachability)
  Layer 7: Risk scoring with confidence
"""

import logging
import requests
from typing import Optional

from core.models import (
    ScanResult,
    Device,
    PortMapping,
    UPnPLeak,
    ExposureFinding,
    DeviceRiskFinding,
    ExternalVerification,
)
from analysis.scorer import RiskScorer
from analysis.upnp import UPnPScanner
from core.onvif import ONVIFProbe
from core.verifier import ExternalVerifier
from plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class LogicEngine:

    def __init__(self, plugins: list[BasePlugin] = None):
        self.scorer  = RiskScorer()
        self.upnp    = UPnPScanner()
        self.onvif   = ONVIFProbe()
        self.plugins = plugins or []

    def analyse(self, result: ScanResult) -> ScanResult:
        """
        Full analysis pipeline:
        1. ONVIF enrichment — confirm cameras
        2. UPnP scan — get confirmed router mappings
        3. Exposure correlation — match mappings to devices
        4. External verification — confirm reachability (if not CGNAT)
        5. Risk scoring — score all devices with confidence
        6. Plugin hooks
        Returns enriched ScanResult.
        """
        logger.info("=" * 50)
        logger.info("Logic Engine starting analysis...")

        logger.info("Layer 2: ONVIF camera probe...")
        result.devices = self.onvif.enrich_devices(result.devices)
        camera_count   = sum(1 for d in result.devices if d.is_camera)
        if camera_count:
            logger.info(f"  ONVIF confirmed {camera_count} camera(s)")

        logger.info("Layer 3: UPnP IGD scan...")
        upnp_leaks       = self.upnp.scan()
        result.upnp_leaks = upnp_leaks
        result.mappings   = [self._leak_to_mapping(leak) for leak in upnp_leaks]
        logger.info(f"  Found {len(result.mappings)} confirmed router mapping(s)")

        logger.info("Layer 4: Correlating devices with router mappings...")
        device_mapping_pairs = self._correlate(result.devices, result.mappings)
        mapped_ips = {device.ip for device, _ in device_mapping_pairs}
        logger.info(
            f"  {len(device_mapping_pairs)} device(s) matched to router mappings"
        )
        verifications: dict[tuple, ExternalVerification] = {}

        if result.wan_ip and device_mapping_pairs:
            verifier = ExternalVerifier(result.wan_ip)

            if verifier.is_cgnat():
                logger.warning(
                    "CGNAT detected — external verification skipped. "
                    "Mappings still flagged — they should be removed."
                )
            else:
                logger.info("Layer 5: External verification...")
                for device, mapping in device_mapping_pairs:
                    key          = (mapping.internal_ip, mapping.internal_port)
                    verification = verifier.verify(mapping)
                    verifications[key] = verification
        else:
            if not result.wan_ip:
                logger.info(
                    "Layer 5: Skipped — WAN IP not available. "
                    "Mappings still flagged."
                )
        logger.info("Layer 7: Risk scoring...")

        # Score devices WITH confirmed mappings → ExposureFinding
        exposure_findings = []
        for device, mapping in device_mapping_pairs:
            key          = (mapping.internal_ip, mapping.internal_port)
            verification = verifications.get(key)

            score, confidence, reasons, remediation = self.scorer.score_exposure(
                device=device,
                mapping=mapping,
                verification=verification,
            )

            finding = ExposureFinding(
                device=device,
                mapping=mapping,
                verification=verification,
                risk_score=score,
                severity=RiskScorer.label(score),
                confidence=confidence,
                reasons=reasons,
                remediation=remediation,
            )
            exposure_findings.append(finding)

            logger.warning(
                f"EXPOSURE: {device.ip} → external:{mapping.external_port} "
                f"— {finding.severity} {score}/10 "
                f"({RiskScorer.confidence_label(confidence)})"
            )
        device_findings = []
        for device in result.devices:
            if device.ip in mapped_ips:
                continue  # already scored above

            score, confidence, reasons, remediation = self.scorer.score_device(
                device=device,
            )

            finding = DeviceRiskFinding(
                device=device,
                risk_score=score,
                severity=RiskScorer.label(score),
                confidence=confidence,
                reasons=reasons,
                remediation=remediation,
            )
            device_findings.append(finding)

            if score >= 7:
                logger.warning(
                    f"{finding.severity}: {device.ip} "
                    f"— score {score}/10 (internal risk, no mapping)"
                )
        result.exposure_findings = sorted(
            exposure_findings, key=lambda f: f.risk_score, reverse=True
        )
        result.device_findings = sorted(
            device_findings, key=lambda f: f.risk_score, reverse=True
        )

        for finding in result.exposure_findings:
            if finding.risk_score >= 7:
                for plugin in self.plugins:
                    try:
                        plugin.on_critical_found(finding)
                    except Exception as e:
                        logger.warning(
                            f"Plugin {plugin.name} on_critical_found error: {e}"
                        )

        critical_exp  = len([f for f in result.exposure_findings if f.severity == "CRITICAL"])
        high_exp      = len([f for f in result.exposure_findings if f.severity == "HIGH"])
        critical_dev  = len([f for f in result.device_findings  if f.severity == "CRITICAL"])
        confirmed     = len([f for f in result.exposure_findings if f.confidence == 100])

        logger.info("=" * 50)
        logger.info(
            f"Analysis complete:\n"
            f"  Devices scanned:          {len(result.devices)}\n"
            f"  Router mappings found:    {len(result.mappings)}\n"
            f"  Exposure findings:        {len(result.exposure_findings)} "
            f"({critical_exp} CRITICAL, {high_exp} HIGH)\n"
            f"  Confirmed reachable:      {confirmed}\n"
            f"  Internal-only findings:   {len(result.device_findings)} "
            f"({critical_dev} CRITICAL)\n"
            f"  CGNAT:                    {self._is_cgnat(result.wan_ip)}"
        )
        logger.info("=" * 50)

        return result

    def _correlate(
        self,
        devices:  list[Device],
        mappings: list[PortMapping],
    ) -> list[tuple[Device, PortMapping]]:
        """
        Match confirmed router mappings to local devices by IP.
        Handles port translation (e.g. external 10554 → internal 554).
        One device can have multiple mappings — one pair per mapping.
        """
        pairs = []
        device_map = {d.ip: d for d in devices}

        for mapping in mappings:
            device = device_map.get(mapping.internal_ip)

            if device:
                pairs.append((device, mapping))
                logger.debug(
                    f"  Correlated: {device.ip}:{mapping.internal_port} "
                    f"→ external:{mapping.external_port}"
                )
            else:
                # Mapping exists but no device found at that IP
                # Device may be offline or IP changed since mapping was created
                logger.warning(
                    f"  Orphan mapping: {mapping.internal_ip}:{mapping.internal_port} "
                    f"→ external:{mapping.external_port} — no device found at that IP. "
                    f"This mapping should still be removed from the router."
                )

        return pairs

    def _leak_to_mapping(self, leak: UPnPLeak) -> PortMapping:
        """
        Convert a UPnPLeak (from upnp.py) to a PortMapping
        (used by scorer and verifier).
        Both represent the same router mapping — just different
        model types for different layers.
        """
        return PortMapping(
            internal_ip=leak.internal_ip,
            internal_port=leak.internal_port,
            external_port=leak.external_port,
            protocol=leak.protocol,
            description=leak.description,
            source=leak.source,
            lease_duration=leak.lease_duration,
        )

    def rescore_all(self, result: ScanResult) -> ScanResult:
        """
        Re-run risk scoring after a fingerprint database update.
        Preserves existing mappings and verifications.
        """
        # Re-score exposure findings with existing verifications
        for finding in result.exposure_findings:
            score, confidence, reasons, remediation = self.scorer.score_exposure(
                device=finding.device,
                mapping=finding.mapping,
                verification=finding.verification,
            )
            finding.risk_score  = score
            finding.severity    = RiskScorer.label(score)
            finding.confidence  = confidence
            finding.reasons     = reasons
            finding.remediation = remediation

        # Re-score device findings
        for finding in result.device_findings:
            score, confidence, reasons, remediation = self.scorer.score_device(
                device=finding.device,
            )
            finding.risk_score  = score
            finding.severity    = RiskScorer.label(score)
            finding.confidence  = confidence
            finding.reasons     = reasons
            finding.remediation = remediation

        result.exposure_findings.sort(key=lambda f: f.risk_score, reverse=True)
        result.device_findings.sort(key=lambda f: f.risk_score, reverse=True)
        return result

    def _is_cgnat(self, wan_ip: str) -> bool:
        if not wan_ip:
            return False
        try:
            parts = [int(x) for x in wan_ip.split(".")]
            return parts[0] == 100 and 64 <= parts[1] <= 127
        except Exception:
            return False