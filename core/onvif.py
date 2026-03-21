"""
onvif.py
Sends WS-Discovery and ONVIF GetDeviceInformation probes
to confirm whether a device is a camera and extract metadata

ONVIF is the standard protocol used by 90%+ of IP cameras
(Hikvision, Dahua, Axis, Reolink, Foscam, Amcrest etc.)
"""

import socket
import logging
import re
import requests
from typing import Optional

logger = logging.getLogger(__name__)

ONVIF_TIMEOUT  = 3
WS_DISC_PORT   = 3702
WS_DISC_ADDR   = "239.255.255.250"

# WS-Discovery probe message
WS_DISCOVERY_MSG = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:muhafiz-probe-001</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

# ONVIF GetDeviceInformation SOAP request
ONVIF_DEVICE_INFO = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetDeviceInformation
        xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>"""


class ONVIFProbe:

    def discover(self) -> list[str]:
        """
        Broadcast WS-Discovery probe on the LAN.
        Returns list of IP addresses that responded as ONVIF devices.
        """
        logger.info("Running WS-Discovery broadcast for ONVIF cameras...")
        found = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(ONVIF_TIMEOUT)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(
                WS_DISCOVERY_MSG.encode(),
                (WS_DISC_ADDR, WS_DISC_PORT)
            )

            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    if ip not in found:
                        found.append(ip)
                        logger.info(f"  ONVIF device discovered: {ip}")
                except socket.timeout:
                    break

            sock.close()

        except Exception as e:
            logger.debug(f"WS-Discovery error: {e}")

        logger.info(f"WS-Discovery found {len(found)} ONVIF device(s)")
        return found

    def probe(self, ip: str) -> Optional[dict]:
        """
        Probe a specific device IP for ONVIF support.
        Tries common ONVIF service paths.
        Returns device info dict if confirmed ONVIF camera, None otherwise.
        """
        # Common ONVIF device service paths
        paths = [
            "/onvif/device_service",
            "/onvif/services",
            "/onvif/device",
            "/onvif",
            "/Device",
        ]

        for path in paths:
            result = self._get_device_info(ip, path)
            if result:
                logger.info(
                    f"ONVIF confirmed: {ip}{path} — "
                    f"{result.get('manufacturer', 'unknown')} "
                    f"{result.get('model', '')}"
                )
                return result

        logger.debug(f"No ONVIF response from {ip}")
        return None

    def _get_device_info(self, ip: str, path: str) -> Optional[dict]:
        """
        Send ONVIF GetDeviceInformation SOAP request.
        Returns parsed device info dict or None.
        """
        for port in [80, 8080, 8000, 2020]:
            try:
                url = f"http://{ip}:{port}{path}"
                response = requests.post(
                    url,
                    data=ONVIF_DEVICE_INFO,
                    headers={
                        "Content-Type": "application/soap+xml",
                        "charset":      "utf-8",
                    },
                    timeout=ONVIF_TIMEOUT,
                )

                if response.status_code in (200, 400, 401):
                    # Even 401 confirms ONVIF is present
                    info = self._parse_device_info(response.text)
                    info["onvif_url"]  = url
                    info["http_port"]  = port
                    info["confirmed"]  = True
                    return info

            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception as e:
                logger.debug(f"ONVIF probe {ip}:{port}{path} error: {e}")
                continue

        return None

    def _parse_device_info(self, xml: str) -> dict:
        """
        Extract device info fields from ONVIF XML response.
        Handles both successful responses and auth-required responses.
        """
        info = {
            "manufacturer": "",
            "model":        "",
            "firmware":     "",
            "serial":       "",
            "hardware":     "",
        }
        fields = {
            "manufacturer": r"<[^>]*Manufacturer[^>]*>([^<]+)<",
            "model":        r"<[^>]*Model[^>]*>([^<]+)<",
            "firmware":     r"<[^>]*FirmwareVersion[^>]*>([^<]+)<",
            "serial":       r"<[^>]*SerialNumber[^>]*>([^<]+)<",
            "hardware":     r"<[^>]*HardwareId[^>]*>([^<]+)<",
        }

        for key, pattern in fields.items():
            match = re.search(pattern, xml, re.IGNORECASE)
            if match:
                info[key] = match.group(1).strip()

        return info

    def is_camera(self, ip: str) -> bool:
        """Quick check — returns True if device responds to ONVIF."""
        return self.probe(ip) is not None

    def enrich_devices(self, devices: list) -> list:
        """
        Run ONVIF probes on all discovered devices.
        Updates device.is_camera and device.onvif_info
        for any that respond.
        Returns the same device list with ONVIF data filled in.
        """
        # First do a broadcast discovery to get known ONVIF IPs fast
        onvif_ips = set(self.discover())

        for device in devices:
            #Check if WS-Discovery already confirmed this IP
            if device.ip in onvif_ips:
                info = self.probe(device.ip) or {}
                device.is_camera  = True
                device.onvif_info = info

                #Update device type and manufacturer if ONVIF gave us better info
                if info.get("manufacturer") and device.ports:
                    for port in device.ports:
                        if port.device_type in ("unknown", "ip_camera"):
                            port.device_type  = "ip_camera"
                            port.manufacturer = info.get("manufacturer", port.manufacturer)

                logger.info(
                    f"ONVIF enriched: {device.ip} — "
                    f"{info.get('manufacturer', 'unknown')} "
                    f"{info.get('model', '')}"
                )
                continue

            #For devices with camera-like ports, try direct probe
            camera_ports = {554, 8000, 8080, 88}
            device_ports = {p.port for p in device.ports}

            if camera_ports & device_ports:
                info = self.probe(device.ip)
                if info:
                    device.is_camera  = True
                    device.onvif_info = info
                    if info.get("manufacturer") and device.ports:
                        for port in device.ports:
                            if port.device_type in ("unknown", "ip_camera"):
                                port.device_type  = "ip_camera"
                                port.manufacturer = info.get(
                                    "manufacturer", port.manufacturer
                                )
                    logger.info(
                        f"ONVIF confirmed via direct probe: {device.ip} — "
                        f"{info.get('manufacturer', 'unknown')}"
                    )

        return devices