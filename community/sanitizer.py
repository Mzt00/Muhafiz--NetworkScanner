"""
sanitizer.py
Strips all identifying information from a finding before
it is ever sent to the community API.
Works with both ExposureFinding and DeviceRiskFinding.
Runs CLIENT-SIDE — data never touches the wire unsanitised.
"""

import re
import logging
from datetime import datetime
from typing import Union

from core.models import (
    ExposureFinding,
    DeviceRiskFinding,
    ContributionPayload,
)

logger = logging.getLogger(__name__)

BANNER_MAX_CHARS = 120
VERSION          = "0.1.0"

# Patterns that could reveal identifying information
REDACT_PATTERNS = [
    # IPv4
    (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"),
     "[ip]"),
    # IPv6
    (re.compile(r"\b([0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b"),
     "[ipv6]"),
    # MAC address
    (re.compile(r"\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"),
     "[mac]"),
    # Serial numbers
    (re.compile(r"\bS/N[:\s]*[A-Z0-9]{6,20}\b", re.IGNORECASE),
     "[serial]"),
    # UUIDs
    (re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
        r"-[0-9a-f]{4}-[0-9a-f]{12}\b",
        re.IGNORECASE
    ), "[uuid]"),
    # Email addresses
    (re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"
    ), "[email]"),
]

# Type alias for either finding type
AnyFinding = Union[ExposureFinding, DeviceRiskFinding]


class Sanitizer: 

    def build_payload(self, finding: AnyFinding) -> ContributionPayload:
        """
        Takes an ExposureFinding or DeviceRiskFinding and returns
        a ContributionPayload with all PII removed.
        Safe to send to the community API.
        """
        open_port = (
            finding.device.ports[0]
            if finding.device.ports
            else None
        )

        if not open_port:
            raise ValueError("Finding device has no open ports.")

        clean_banner = self._clean_banner(open_port.banner)

        # Final IP check — reject if any slipped through
        if self._contains_ip(clean_banner):
            logger.warning(
                "Banner still contained IP after sanitisation — clearing."
            )
            clean_banner = ""

        payload = ContributionPayload(
            port=open_port.port,
            banner_snippet=clean_banner,
            device_type=open_port.device_type,
            manufacturer=open_port.manufacturer,
            risk_score=finding.risk_score,
            client_version=VERSION,
            contributed_at=datetime.utcnow(),
        )

        logger.info(
            f"Sanitized payload: port={payload.port} "
            f"device={payload.device_type} "
            f"risk={payload.risk_score}"
        )
        return payload

    def preview(self, finding: AnyFinding) -> dict:
        """
        Returns exactly what WILL and WON'T be sent.
        Used by the dashboard consent dialog before submission.
        """
        open_port    = finding.device.ports[0] if finding.device.ports else None
        clean_banner = self._clean_banner(open_port.banner if open_port else "")

        will_send = {
            "port":           open_port.port if open_port else None,
            "banner_snippet": clean_banner,
            "device_type":    open_port.device_type if open_port else "unknown",
            "manufacturer":   open_port.manufacturer if open_port else "unknown",
            "risk_score":     finding.risk_score,
            "client_version": VERSION,
        }

        will_strip = {
            "internal_ip": finding.device.ip,
            "mac_address": finding.device.mac,
            "hostname":    finding.device.hostname,
        }

        # For exposure findings, also show what mapping data is stripped
        if isinstance(finding, ExposureFinding):
            will_strip["mapping_internal_ip"] = finding.mapping.internal_ip
            will_strip["external_port"]        = (
                f"stripped (was {finding.mapping.external_port})"
            )

        return {
            "will_send":  will_send,
            "will_strip": will_strip,
        }
    def validate(self, payload: ContributionPayload) -> tuple[bool, str]:
        """
        Final validation before the payload is sent.
        Returns (True, "") if valid, (False, reason) if not.
        """
        if self._contains_ip(payload.banner_snippet):
            return False, "Banner snippet contains an IP address."

        if not 1 <= payload.port <= 65535:
            return False, f"Invalid port number: {payload.port}"

        if not 1 <= payload.risk_score <= 10:
            return False, f"Invalid risk score: {payload.risk_score}"

        if len(payload.banner_snippet) > BANNER_MAX_CHARS:
            return False, (
                f"Banner too long: {len(payload.banner_snippet)} chars "
                f"(max {BANNER_MAX_CHARS})"
            )

        if not payload.device_type or not payload.manufacturer:
            return False, "device_type and manufacturer cannot be empty."

        return True, ""

    def _clean_banner(self, banner: str) -> str: #so any personal information is never uploaded to the community db
        """
        1. Truncate to BANNER_MAX_CHARS
        2. Redact IPs, MACs, serials, UUIDs, emails
        3. Strip non-printable characters
        """
        if not banner:
            return ""

        cleaned = banner[:BANNER_MAX_CHARS]

        for pattern, replacement in REDACT_PATTERNS:
            cleaned = pattern.sub(replacement, cleaned)

        #Strip non-printable characters except newline and tab
        cleaned = re.sub(r"[^\x20-\x7E\t\n]", "", cleaned)

        return cleaned.strip()

    def _contains_ip(self, text: str) -> bool: #final ip address check
        return bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text))