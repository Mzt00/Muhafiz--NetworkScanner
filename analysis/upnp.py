"""
upnp.py
UPnP Leak Detector — Analysis Layer
Queries the router's IGD (Internet Gateway Device) via UPnP
to enumerate all active port mappings. Cross-references them
against Shodan findings to flag leaks.
"""

import socket
import logging
import re
from typing import Optional

import requests

from core.models import UPnPLeak

logger = logging.getLogger(__name__)

# UPnP discovery uses SSDP (Simple Service Discovery Protocol)
SSDP_ADDR    = "239.255.255.250"
SSDP_PORT    = 1900
SSDP_TIMEOUT = 3
SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n"
)


class UPnPScanner:

    def scan(self, exposed_port_nums: set[int] = None) -> list[UPnPLeak]:
        """
        Discover the router via SSDP, fetch its port mapping table,
        and return a list of UPnPLeak objects for any mapping whose
        external port appears in the Shodan exposed ports set.

        Args:
            exposed_port_nums: set of port numbers Shodan found open
                               on your WAN IP. If None, returns all
                               mappings regardless.
        Returns:
            list of UPnPLeak objects
        """
        logger.info("UPnP scanner starting...")

        control_url = self._discover_igd()
        if not control_url:
            logger.info("No UPnP IGD found on network — router may have UPnP disabled.")
            return []

        logger.info(f"IGD found at: {control_url}")
        mappings = self._get_port_mappings(control_url)

        if not mappings:
            logger.info("No active UPnP port mappings found.")
            return []

        logger.info(f"Found {len(mappings)} UPnP port mapping(s)")

        leaks = []
        for m in mappings:
            ext_port = m.get("external_port", 0)

            # Flag if this port is also visible on Shodan
            is_leak = (
                exposed_port_nums is None
                or ext_port in exposed_port_nums
            )

            if is_leak:
                leak = UPnPLeak(
                    internal_ip=m.get("internal_ip", "unknown"),
                    internal_port=m.get("internal_port", 0),
                    external_port=ext_port,
                    protocol=m.get("protocol", "TCP"),
                    description=m.get("description", ""),
                    lease_duration=m.get("lease_duration", 0),
                )
                leaks.append(leak)
                logger.warning(
                    f"UPnP LEAK: {leak.internal_ip}:{leak.internal_port} "
                    f"→ external port {leak.external_port}/{leak.protocol} "
                    f"— '{leak.description}'"
                )

        logger.info(f"UPnP scan complete — {len(leaks)} leak(s) found")
        return leaks

    def _discover_igd(self) -> Optional[str]:
        """
        Broadcast SSDP M-SEARCH to find the router's IGD.
        Returns the control URL string or None if not found.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(SSDP_TIMEOUT)
            sock.sendto(SSDP_REQUEST.encode(), (SSDP_ADDR, SSDP_PORT))

            response = sock.recv(2048).decode("utf-8", errors="ignore")
            sock.close()

            # Extract the LOCATION header — points to the IGD description XML
            location = self._parse_header(response, "LOCATION")
            if not location:
                return None

            return self._get_control_url(location)

        except socket.timeout:
            logger.info("SSDP discovery timed out — no IGD responded.")
            return None
        except Exception as e:
            logger.warning(f"SSDP discovery error: {e}")
            return None

    def _get_control_url(self, location: str) -> Optional[str]:
        """
        Fetch the IGD description XML from the LOCATION URL
        and extract the WANIPConnection control URL.
        """
        try:
            response = requests.get(location, timeout=5)
            xml = response.text

            # Look for WANIPConnection or WANPPPConnection service
            match = re.search(
                r"<controlURL>\s*([^<]+)\s*</controlURL>",
                xml
            )
            if not match:
                return None

            control_path = match.group(1).strip()

            # Build the full control URL from the base location
            base = "/".join(location.split("/")[:3])
            return base + control_path

        except Exception as e:
            logger.warning(f"Could not fetch IGD description: {e}")
            return None

    def _get_port_mappings(self, control_url: str) -> list[dict]:
        """
        Enumerate all port mappings via UPnP SOAP calls.
        Iterates index 0, 1, 2... until the router returns an error.
        Returns list of mapping dicts.
        """
        mappings = []
        index = 0

        while True:
            soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetGenericPortMappingEntry
        xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewPortMappingIndex>{index}</NewPortMappingIndex>
    </u:GetGenericPortMappingEntry>
  </s:Body>
</s:Envelope>"""

            try:
                response = requests.post(
                    control_url,
                    data=soap_body,
                    headers={
                        "Content-Type": "text/xml",
                        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"',
                    },
                    timeout=5,
                )

                # 500 with SpecifiedArrayIndexInvalid = no more entries
                if response.status_code == 500:
                    break

                mapping = self._parse_mapping(response.text)
                if mapping:
                    mappings.append(mapping)
                    index += 1
                else:
                    break

            except Exception as e:
                logger.debug(f"Port mapping fetch stopped at index {index}: {e}")
                break

        return mappings

    def _parse_mapping(self, xml: str) -> Optional[dict]:
        """Extract port mapping fields from a SOAP XML response."""
        def extract(tag: str) -> str:
            m = re.search(fr"<NewRemoteHost>|<{tag}>([^<]*)</{tag}>", xml)
            if not m:
                m = re.search(fr"<{tag}>([^<]*)</{tag}>", xml)
            return m.group(1).strip() if m else ""

        try:
            return {
                "internal_ip":    extract("NewInternalClient"),
                "internal_port":  int(extract("NewInternalPort") or 0),
                "external_port":  int(extract("NewExternalPort") or 0),
                "protocol":       extract("NewProtocol"),
                "description":    extract("NewPortMappingDescription"),
                "lease_duration": int(extract("NewLeaseDuration") or 0),
                "enabled":        extract("NewEnabled") == "1",
            }
        except Exception:
            return None

    def _parse_header(self, response: str, header: str) -> Optional[str]:
        """Extract a header value from an HTTP response string."""
        match = re.search(
            fr"^{header}:\s*(.+)$",
            response,
            re.IGNORECASE | re.MULTILINE
        )
        return match.group(1).strip() if match else None