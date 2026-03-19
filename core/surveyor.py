"""
surveyor.py
Module B - The Surveyor
Performs ARP ping sweep across the local subnet to discover
all connected devices, then runs Nmap service detection on each.
"""

import logging
import socket
import sys
import os
import ctypes
import subprocess
from typing import Optional

import nmap
from scapy.all import ARP, Ether, srp

from core.models import Device, OpenPort

logger = logging.getLogger(__name__)


def elevate_if_needed():
    """
    If not running as admin on Windows, re-launch the current script
    with a UAC elevation prompt (the standard Windows 'Run as administrator'
    dialogue box). The original process exits cleanly.
    """
    if sys.platform != "win32":
        return

    if ctypes.windll.shell32.IsUserAnAdmin():
        return

    # Re-launch with ShellExecute runas verb — triggers the UAC dialogue
    script = sys.argv[0]
    params = " ".join(sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(
        None,       # parent window handle
        "runas",    # verb — triggers UAC
        sys.executable,
        f'"{script}" {params}',
        None,       # working directory (use current)
        1           # SW_NORMAL — show the window normally
    )
    sys.exit(0)


class SurveyorScanner:

    def __init__(self, subnet: Optional[str] = None):
        """
        subnet: e.g. "192.168.1.0/24"
        If not provided, auto-detects from the machine's local IP.
        """
        self.subnet = subnet or self._detect_subnet()
        self.nm = nmap.PortScanner()


   #check if runnning with enough privileges

    def check_privileges(self) -> bool:
        """
        ARP scanning requires root/admin privileges.
        Returns True if we have them, False otherwise.
        """
        if sys.platform == "win32":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0


    def _detect_subnet(self) -> str:
        """
        Guess the local subnet from the machine's own IP.
        e.g. if machine is 192.168.1.105 returns 192.168.1.0/24
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            logger.info(f"Auto-detected subnet: {subnet}")
            return subnet
        except Exception as e:
            raise RuntimeError(f"Could not detect local subnet: {e}")


    def _arp_sweep(self) -> list[dict]:
        """
        Send ARP requests to every IP in the subnet.
        Returns list of dicts with 'ip' and 'mac'.
        """
        logger.info(f"Running ARP sweep on {self.subnet}...")

        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
        answered, _ = srp(packet, timeout=3, verbose=False)

        hosts = []
        for sent, received in answered:
            hosts.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
            })
            logger.debug(f"  Found host: {received.psrc} ({received.hwsrc})")

        logger.info(f"ARP sweep found {len(hosts)} host(s)")
        return hosts


    def _get_hostname(self, ip: str) -> str:
        """Reverse DNS lookup for a given IP. Returns empty string if not found."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ""



    def _nmap_scan(self, ip: str) -> list[OpenPort]:
        """
        Run Nmap -sV (service version detection) on a single host.
        Returns a list of OpenPort objects.
        """
        logger.info(f"  Running Nmap on {ip}...")
        ports = []

        try:
            self.nm.scan(
                hosts=ip,
                arguments="-sV --open -T4 --host-timeout 30s"
            )

            if ip not in self.nm.all_hosts():
                return []

            for proto in self.nm[ip].all_protocols():
                for port_num, port_info in self.nm[ip][proto].items():
                    if port_info["state"] != "open":
                        continue

                    open_port = OpenPort(
                        port=port_num,
                        protocol=proto,
                        service=port_info.get("name", "unknown"),
                        banner=f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                        device_type="unknown",
                        manufacturer="unknown",
                    )
                    ports.append(open_port)
                    logger.debug(f"    Port {port_num}/{proto} — {open_port.service} {open_port.banner}")

        except nmap.PortScannerError as e:
            logger.warning(f"  Nmap error on {ip}: {e}")

        return ports


    def scan(self) -> list[Device]:
        """
        Full LAN scan:
        1. Check privileges — triggers UAC prompt on Windows if needed
        2. ARP sweep to find all live hosts
        3. Reverse DNS for hostnames
        4. Nmap service detection on each host
        Returns a list of Device objects.
        """
        # Trigger UAC elevation dialogue on Windows if not admin
        elevate_if_needed()

        if not self.check_privileges():
            raise PermissionError(
                "Administrator privileges required. "
                "Please re-run as administrator."
            )

        raw_hosts = self._arp_sweep()

        if not raw_hosts:
            logger.warning("No hosts found on subnet. Check your subnet setting in .env")
            return []

        devices = []
        for host in raw_hosts:
            ip = host["ip"]
            mac = host["mac"]
            hostname = self._get_hostname(ip)
            open_ports = self._nmap_scan(ip)

            device = Device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                ports=open_ports,
            )
            devices.append(device)
            logger.info(f"Device: {ip} | {mac} | {hostname} | {len(open_ports)} port(s)")

        logger.info(f"Surveyor complete — {len(devices)} device(s) found")
        return devices