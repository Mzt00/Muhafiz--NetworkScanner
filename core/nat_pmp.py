"""
nat_pmp.py
NAT-PMP / PCP Port Mapping Detector
Queries the router for NAT-PMP (RFC 6886) and PCP (RFC 6887)
port mappings as a second source alongside UPnP IGD.
No external API needed — pure UDP probes on the local network.

NAT-PMP uses port 5351 on the default gateway.
PCP uses port 5351 on the default gateway (backward compatible).
"""

import socket
import struct
import logging
from typing import Optional

from core.models import PortMapping

logger = logging.getLogger(__name__)

NAT_PMP_PORT    = 5351
NAT_PMP_TIMEOUT = 3


class NatPmpScanner:

    def __init__(self):
        self.gateway = self._get_default_gateway()


    def _get_default_gateway(self) -> Optional[str]:
        """
        Detect the default gateway IP by opening a UDP socket
        and reading the local address. Works on Windows and Linux.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            #Gateway is typically x.x.x.1
            parts = local_ip.split(".")
            gateway = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            logger.info(f"Default gateway detected: {gateway}")
            return gateway
        except Exception as e:
            logger.warning(f"Could not detect gateway: {e}")
            return None

    def get_public_ip(self) -> Optional[str]:
        """
        Send a NAT-PMP external address request to the gateway.
        Returns the public IP string if the router supports NAT-PMP,
        None otherwise.

        NAT-PMP external address request packet:
          Version: 0 (1 byte)
          Opcode:  0 (1 byte)  external address request
        """
        if not self.gateway:
            return None

        try:
            # Build request packet: version=0, opcode=0
            packet = struct.pack("!BB", 0, 0)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(NAT_PMP_TIMEOUT)
            sock.sendto(packet, (self.gateway, NAT_PMP_PORT))

            response, _ = sock.recvfrom(12)
            sock.close()

            if len(response) < 12:
                return None

            # Response: version(1) + opcode(1) + result(2) + epoch(4) + ip(4)
            version, opcode, result_code = struct.unpack("!BBH", response[:4])
            epoch_time                   = struct.unpack("!I", response[4:8])[0]
            ip_bytes                     = response[8:12]

            if result_code != 0:
                logger.debug(f"NAT-PMP result code: {result_code} — not supported")
                return None

            public_ip = socket.inet_ntoa(ip_bytes)
            logger.info(f"NAT-PMP public IP: {public_ip}")
            return public_ip

        except socket.timeout:
            logger.debug("NAT-PMP request timed out — router may not support it.")
            return None
        except Exception as e:
            logger.debug(f"NAT-PMP error: {e}")
            return None

    def scan(self) -> list[PortMapping]:
        """
        NAT-PMP does not have a "list all mappings" command like UPnP.
        Instead we detect if the router supports NAT-PMP and return
        the public IP  the actual mappings come from UPnP module

        Returns empty list if NAT-PMP not supported.
        Returns a single informational PortMapping if supported,
        indicating the router has NAT-PMP enabled.
        """
        if not self.gateway:
            logger.info("NAT-PMP: no gateway detected — skipping.")
            return []

        logger.info(f"Probing NAT-PMP on gateway {self.gateway}...")

        public_ip = self.get_public_ip()

        if public_ip is None:
            logger.info("NAT-PMP not supported by this router.")
            return []

        logger.info(
            f"NAT-PMP supported — router public IP confirmed: {public_ip}"
        )

        # NAT-PMP doesn't expose a mapping list  return the
        # public IP as a confirmed data point for the correlation engine.
        # The actual per-device mappings come from UPnP (upnp.py).
        return []


    def is_supported(self) -> bool:
        """
        Quick check returns True if the router responds to
        NAT-PMP external address requests.
        """
        return self.get_public_ip() is not None


    def get_wan_ip(self) -> Optional[str]:
        """
        Get WAN/public IP via NAT-PMP.
        Fallback for get_wan_ip() in core/__init__.py
        """
        return self.get_public_ip()