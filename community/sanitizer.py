"""
sanitizer.py
Community Layer
It sits as a mandatory gate between the scan result and the
network. No contribution payload can be built without going
through this file first.

What it strips:
    - WAN IP address
    - Internal IP address
    - MAC address (full)
    - Hostname
    - Router model
    - Geolocation
    - Any IP, MAC, UUID, serial number, or email
      that accidentally appears inside a banner string

What it keeps:
    - Port number
    - Banner snippet (truncated, redacted)
    - Device type  (e.g. "ip_camera")
    - Manufacturer (e.g. "Hikvision")
    - Risk score   (1-10)
    - Shodan match (True/False)
    - Client version string

Flow:
    CriticalCorrelation
         Sanitizer.build_payload()
             _clean_banner()     strips IPs/MACs from banner text
             _contains_ip()      final safety check
             validate()          confirms payload is safe to send
         ContributionPayload     ready for community API
"""

import re
import logging
from datetime import datetime

from core.models import CriticalCorrelation, ContributionPayload

logger = logging.getLogger(__name__)
# Current client version — sent with every contribution
# so the API knows which fingerprint schema was used
VERSION = "0.1.0"

# Maximum banner length sent to the API.
# Keeps payloads small and reduces risk of accidental
# PII leaking through long verbose banners.
BANNER_MAX_CHARS = 120

# Applied to banner strings before they leave the machine.
# Each tuple is (compiled_regex, replacement_string).
# Order matters — IPs are redacted before MACs to avoid
# partial matches creating confusing output.

REDACT_PATTERNS = [
    # IPv4 addresses — e.g. 192.168.1.50 or 203.0.113.47
    (
        re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"),
        "[ip]"
    ),
    # IPv6 addresses — e.g. 2001:0db8:85a3::8a2e:0370:7334
    (
        re.compile(r"\b([0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b"),
        "[ipv6]"
    ),
    # MAC addresses — e.g. aa:bb:cc:11:22:33 or aa-bb-cc-11-22-33
    (
        re.compile(r"\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"),
        "[mac]"
    ),
    # Serial numbers — e.g. S/N: A1B2C3D4E5
    (
        re.compile(r"\bS/?N[:\s]*[A-Z0-9]{6,20}\b", re.IGNORECASE),
        "[serial]"
    ),
    # UUIDs — e.g. 550e8400-e29b-41d4-a716-446655440000
    (
        re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
            r"-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE
        ),
        "[uuid]"
    ),
    # Email addresses — e.g. admin@camera.local
    (
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"
        ),
        "[email]"
    ),
]


class Sanitizer:
    """
    Converts a CriticalCorrelation into a safe ContributionPayload.

    Usage:
        sanitizer = Sanitizer()

        # See what will and won't be sent (for consent UI)
        preview = sanitizer.preview(correlation)

        # Build the actual payload
        payload = sanitizer.build_payload(correlation)

        # Validate before sending
        ok, reason = sanitizer.validate(payload)
        if ok:
            # send payload to API
    """

    def build_payload(
        self,
        correlation: CriticalCorrelation,
        shodan_match: bool = True,
    ) -> ContributionPayload:
        """
        Takes a CriticalCorrelation and returns a ContributionPayload
        with all PII stripped out.

        Args:
            correlation:  A CriticalCorrelation from the Logic Engine.
                          Contains the device, exposed port, risk score.
            shodan_match: Whether this finding matched a Shodan result.
                          Almost always True for correlations.

        Returns:
            ContributionPayload — safe to send to the community API.

        Raises:
            ValueError: if the correlation has no open ports to work with.
        """
        # Get the first open port on the device —
        # this is the port that was correlated with Shodan
        open_port = (
            correlation.device.ports[0]
            if correlation.device.ports
            else None
        )

        if not open_port:
            raise ValueError(
                "Correlation device has no open ports — "
                "cannot build contribution payload."
            )

        # Clean the banner strip IPs, MACs, truncate
        clean_banner = self._clean_banner(open_port.banner)

        # Final IP check  if anything slipped through, clear the banner
        # entirely rather than risk sending identifying data
        if self._contains_ip(clean_banner):
            logger.warning(
                f"Banner for port {open_port.port} still contained an IP "
                f"after sanitisation — clearing banner entirely."
            )
            clean_banner = ""

        payload = ContributionPayload(
            port=open_port.port,
            banner_snippet=clean_banner,
            device_type=open_port.device_type,
            manufacturer=open_port.manufacturer,
            risk_score=correlation.risk_score,
            shodan_match=shodan_match,
            client_version=VERSION,
            contributed_at=datetime.utcnow(),
        )

        logger.info(
            f"Sanitizer: payload built — "
            f"port={payload.port} "
            f"device_type={payload.device_type} "
            f"manufacturer={payload.manufacturer} "
            f"risk_score={payload.risk_score} "
            f"banner_len={len(payload.banner_snippet)}"
        )

        return payload

    def _clean_banner(self, banner: str) -> str:
        """
        Cleans a raw device banner string for safe transmission.

        Steps:
        1. Truncate to BANNER_MAX_CHARS  prevents large banners
           from accidentally containing personal data further down
        2. Apply all REDACT_PATTERNS replaces IPs, MACs, serials,
           UUIDs, and emails with safe placeholder strings like [ip]
        3. Strip non-printable characters removes binary garbage
           that could cause encoding issues on the API side

        Args:
            banner: Raw banner string from the Banner Grabber.

        Returns:
            Cleaned, safe banner string.
        """
        if not banner:
            return ""

        
        cleaned = banner[:BANNER_MAX_CHARS]

        for pattern, replacement in REDACT_PATTERNS:
            cleaned = pattern.sub(replacement, cleaned)

        # Keep standard printable ASCII (0x20-0x7E) plus tab and newline
        cleaned = re.sub(r"[^\x20-\x7E\t\n]", "", cleaned)

        return cleaned.strip()

  

    def _contains_ip(self, text: str) -> bool:
        """
        Final safety check after cleaning.
        Returns True if the text still contains anything
        that looks like an IPv4 address.

        Args:
            text: The cleaned banner string.

        Returns:
            True if an IP address pattern is found, False if clean.
        """
        return bool(
            re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)
        )

    def preview(self, correlation: CriticalCorrelation) -> dict:
        """
        Returns a dict showing EXACTLY what will and won't be sent.
        This is what populates the consent dialog in the dashboard —
        the user sees this before approving a contribution.

        The 'will_send' section shows the sanitised payload.
        The 'will_strip' section shows what is being removed,
        so the user can verify their private data stays local.

        Args:
            correlation: The CriticalCorrelation to preview.

        Returns:
            dict with 'will_send' and 'will_strip' keys.
        """
        open_port = (
            correlation.device.ports[0]
            if correlation.device.ports
            else None
        )
        clean_banner = self._clean_banner(
            open_port.banner if open_port else ""
        )

        return {
            "will_send": {
                "port":           open_port.port if open_port else None,
                "banner_snippet": clean_banner,
                "device_type":    open_port.device_type if open_port else "unknown",
                "manufacturer":   open_port.manufacturer if open_port else "unknown",
                "risk_score":     correlation.risk_score,
                "shodan_match":   True,
                "client_version": VERSION,
            },
            "will_strip": {
                "wan_ip":      "redacted — never sent",
                "internal_ip": correlation.device.ip,
                "mac_address": correlation.device.mac,
                "hostname":    correlation.device.hostname,
            },
        }


    def validate(self, payload: ContributionPayload) -> tuple[bool, str]:
        """
        Final validation gate before a payload is sent to the API.
        Called by client.py immediately before the POST request.

        Checks:
        - No IP addresses in the banner snippet
        - Port number is in valid range (1-65535)
        - Risk score is in valid range (1-10)
        - Banner snippet is not over the length limit
        - device_type and manufacturer are not empty strings

        Args:
            payload: The ContributionPayload to validate.

        Returns:
            (True, "")           if payload is safe to send
            (False, reason_str)  if validation failed, with reason
        """
        if self._contains_ip(payload.banner_snippet):
            return False, "Banner snippet still contains an IP address."

        if not 1 <= payload.port <= 65535:
            return False, f"Invalid port number: {payload.port}"

        if not 1 <= payload.risk_score <= 10:
            return False, f"Invalid risk score: {payload.risk_score}"

        if len(payload.banner_snippet) > BANNER_MAX_CHARS:
            return False, (
                f"Banner snippet too long: "
                f"{len(payload.banner_snippet)} chars "
                f"(max {BANNER_MAX_CHARS})"
            )

        if not payload.device_type or not payload.manufacturer:
            return False, "device_type and manufacturer cannot be empty."

        return True, ""