"""
verifier.py
Only called when a confirmed port mapping exists.
Attempts to connect to WAN_IP:external_port to verify
whether the device is actually reachable from outside.
No external API needed — pure socket connections.
"""

import socket
import logging
import requests
from datetime import datetime
from typing import Optional

from core.models import PortMapping, ExternalVerification

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 5
BANNER_MAX_BYTES = 512

# RTSP OPTIONS probe — cameras respond to this
RTSP_PROBE = (
    "OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
    "CSeq: 1\r\n"
    "User-Agent: Muhafiz\r\n"
    "\r\n"
)

# HTTP GET probe
HTTP_PROBE = (
    "GET / HTTP/1.0\r\n"
    "Host: {ip}\r\n"
    "User-Agent: Muhafiz\r\n"
    "\r\n"
)


class ExternalVerifier:

    def __init__(self, wan_ip: str):
        """
        wan_ip: the public IP of the network being scanned.
        Obtained from NAT-PMP or ipify — passed in from core/__init__.py
        """
        self.wan_ip = wan_ip

    def verify(self, mapping: PortMapping) -> ExternalVerification:
        """
        Attempt to connect to WAN_IP:external_port.
        Tries the most appropriate probe based on port/service type.
        Returns ExternalVerification with reachable=True/False.

        IMPORTANT: Only called when a confirmed mapping exists.
        Never called on devices without a router mapping.
        """
        ext_port = mapping.external_port
        protocol = mapping.protocol.lower()

        logger.info(
            f"Verifying external access: {self.wan_ip}:{ext_port} "
            f"({protocol}) → internal {mapping.internal_ip}:{mapping.internal_port}"
        )

        # Choose probe based on internal port
        internal_port = mapping.internal_port

        if internal_port == 554 or "rtsp" in mapping.description.lower():
            result = self._probe_rtsp(ext_port)
        elif internal_port in (80, 8080, 8000, 443, 8443):
            result = self._probe_http(ext_port)
        else:
            result = self._probe_tcp(ext_port)

        if result["reachable"]:
            logger.warning(
                f"CONFIRMED REACHABLE: {self.wan_ip}:{ext_port} — "
                f"device at {mapping.internal_ip} is accessible from internet"
            )
        else:
            logger.info(
                f"Not reachable externally: {self.wan_ip}:{ext_port} — "
                f"mapping exists but connection failed (firewall or CGNAT)"
            )

        return ExternalVerification(
            wan_ip=self.wan_ip,
            external_port=ext_port,
            protocol=result["protocol"],
            reachable=result["reachable"],
            banner=result["banner"],
            verified_at=datetime.utcnow(),
        )

    def verify_all(
        self,
        mappings: list[PortMapping],
    ) -> dict[tuple, ExternalVerification]:
        """
        Verify all confirmed port mappings.
        Returns dict keyed by (internal_ip, internal_port).
        """
        results = {}
        for mapping in mappings:
            key = (mapping.internal_ip, mapping.internal_port)
            results[key] = self.verify(mapping)
        return results

    def _probe_rtsp(self, ext_port: int) -> dict:
        """
        Send RTSP OPTIONS request to WAN_IP:port.
        RTSP/1.0 200 OK response = camera stream confirmed accessible.
        """
        try:
            probe = RTSP_PROBE.format(ip=self.wan_ip, port=ext_port)
            with socket.create_connection(
                (self.wan_ip, ext_port), timeout=CONNECT_TIMEOUT
            ) as sock:
                sock.sendall(probe.encode())
                banner = sock.recv(BANNER_MAX_BYTES).decode("utf-8", errors="ignore")

                if "RTSP" in banner or "200" in banner or "401" in banner:
                    return {
                        "reachable": True,
                        "protocol":  "rtsp",
                        "banner":    banner[:200],
                    }
                # TCP connected but unexpected response
                return {
                    "reachable": True,
                    "protocol":  "rtsp",
                    "banner":    banner[:200],
                }

        except (socket.timeout, ConnectionRefusedError, OSError):
            # TCP connect failed try HTTP fallback
            return self._probe_http(ext_port)


    def _probe_http(self, ext_port: int) -> dict:
        """
        Send HTTP GET to WAN_IP:port.
        Any response (even 401 Unauthorized) = port is open.
        """
        try:
            probe = HTTP_PROBE.format(ip=self.wan_ip)
            with socket.create_connection(
                (self.wan_ip, ext_port), timeout=CONNECT_TIMEOUT
            ) as sock:
                sock.sendall(probe.encode())
                banner = sock.recv(BANNER_MAX_BYTES).decode("utf-8", errors="ignore")
                return {
                    "reachable": True,
                    "protocol":  "http",
                    "banner":    banner[:200],
                }

        except (socket.timeout, ConnectionRefusedError, OSError):
            return {
                "reachable": False,
                "protocol":  "http",
                "banner":    "",
            }

    def _probe_tcp(self, ext_port: int) -> dict:
        """
        Raw TCP connect to WAN_IP:port.
        If connection succeeds, port is reachable.
        """
        try:
            with socket.create_connection(
                (self.wan_ip, ext_port), timeout=CONNECT_TIMEOUT
            ) as sock:
                # Try to read any banner
                sock.settimeout(2)
                try:
                    banner = sock.recv(BANNER_MAX_BYTES).decode("utf-8", errors="ignore")
                except socket.timeout:
                    banner = ""

                return {
                    "reachable": True,
                    "protocol":  "tcp",
                    "banner":    banner[:200],
                }

        except (socket.timeout, ConnectionRefusedError, OSError):
            return {
                "reachable": False,
                "protocol":  "tcp",
                "banner":    "",
            }



    def is_cgnat(self) -> bool:
        """
        Check if the WAN IP is behind CGNAT (Carrier-Grade NAT).
        CGNAT uses RFC 6598 range: 100.64.0.0/10
        If behind CGNAT, external verification is unreliable.
        """
        if not self.wan_ip:
            return False
        try:
            parts = [int(x) for x in self.wan_ip.split(".")]
            # 100.64.0.0 – 100.127.255.255
            if parts[0] == 100 and 64 <= parts[1] <= 127:
                logger.warning(
                    f"CGNAT detected — WAN IP {self.wan_ip} is in the "
                    f"100.64.0.0/10 range. Direct external exposure unlikely. "
                    f"Your ISP is using shared NAT."
                )
                return True
        except Exception:
            pass
        return False

    def grab_thumbnail(self, mapping: PortMapping) -> Optional[bytes]:
        """
        Attempt to grab a snapshot from an exposed camera.
        Only called for confirmed reachable cameras.
        Tries common snapshot URLs — returns image bytes or None.
        Image is never saved to disk — kept in memory only.
        """
        ext_port = mapping.external_port
        snapshot_paths = [
            "/snapshot.jpg",
            "/cgi-bin/snapshot.cgi",
            "/Streaming/channels/1/picture",   # Hikvision
            "/cgi-bin/currentpic.cgi",          # Axis
            "/snapshot",
            "/image.jpg",
            "/cam/realmonitor?channel=1&subtype=0",  # Dahua
        ]

        for path in snapshot_paths:
            try:
                url = f"http://{self.wan_ip}:{ext_port}{path}"
                response = requests.get(url, timeout=CONNECT_TIMEOUT)

                if response.status_code == 200 and "image" in response.headers.get(
                    "Content-Type", ""
                ):
                    logger.info(f"Thumbnail grabbed from {url}")
                    return response.content

            except Exception:
                continue

        logger.debug(f"No thumbnail available for {self.wan_ip}:{ext_port}")
        return None