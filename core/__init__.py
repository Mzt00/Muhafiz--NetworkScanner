"""
core/__init__.py
Wires together the three scanner modules:
  - GhostScanner   (Shodan WAN)
  - SurveyorScanner (LAN ARP + Nmap)
  - BannerGrabber  (Banner fingerprinting)
"""

import logging
from datetime import datetime

from core.ghost import GhostScanner
from core.surveyor import SurveyorScanner
from core.grabber import BannerGrabber
from core.models import ScanResult

logger = logging.getLogger(__name__)


def run_scan(subnet: str = None) -> ScanResult:
    """
    Run a full Muhafiz scan:
    1. Check internet connectivity
    2. Get WAN IP and query Shodan
    3. ARP sweep the local subnet
    4. Banner grab and fingerprint each device
    5. Return a complete ScanResult

    Args:
        subnet: e.g. "192.168.1.0/24" — auto-detected if not provided

    Returns:
        ScanResult with all devices, exposed ports, ready for analysis
    """

    logger.info("=" * 50)
    logger.info("Muhafiz scan starting...")
    logger.info("=" * 50)
    logger.info("[1/3] Ghost — querying Shodan...")
    ghost = GhostScanner()
    wan_ip = ghost.get_wan_ip()
    exposed_ports = ghost.scan(wan_ip)
    logger.info("[2/3] Surveyor — scanning local network...")
    surveyor = SurveyorScanner(subnet=subnet)
    devices = surveyor.scan()
    logger.info("[3/3] Grabber — fingerprinting devices...")
    grabber = BannerGrabber()
    devices = grabber.enrich_all(devices)

  
    result = ScanResult(
        timestamp=datetime.utcnow(),
        wan_ip=wan_ip,
        subnet=surveyor.subnet,
        devices=devices,
        exposed_ports=exposed_ports,
    )

    logger.info("=" * 50)
    logger.info(
        f"Scan complete — "
        f"{len(devices)} device(s) found, "
        f"{len(exposed_ports)} port(s) exposed on WAN"
    )
    logger.info("=" * 50)

    return result