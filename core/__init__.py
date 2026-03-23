"""
core/__init__.py

Layer order:
  0. Fingerprint auto-update
  1. Plugin loading
  2. LAN discovery (Surveyor)
  3. Banner grabbing + plugin fingerprinting (Grabber)
  4. WAN IP detection (NAT-PMP → ipify fallback)
  5. Analysis engine (ONVIF → UPnP → Correlation → Verification → Scoring)
  6. Plugin on_scan_complete hooks
"""

import logging
import requests
from datetime import datetime

from core.surveyor import SurveyorScanner
from core.grabber import BannerGrabber
from core.nat_pmp import NatPmpScanner
from core.mac_lookup import MacLookup
from core.models import ScanResult
from analysis.updater import FingerprintUpdater
from analysis.engine import LogicEngine
from plugins import load_plugins

logger = logging.getLogger(__name__)


def run_scan(subnet: str = None) -> ScanResult:
    """
    Run a full Muhafiz LAN scan.

    Returns a fully analysed ScanResult with:
      - devices           — all LAN devices with ports + fingerprints
      - mappings          — confirmed router port mappings
      - upnp_leaks        — UPnP leak objects (same data as mappings)
      - exposure_findings — devices matched to mappings + verification
      - device_findings   — internal-risk-only devices (no mapping)
    """

    logger.info("=" * 50)
    logger.info("Muhafiz LAN scan starting...")
    logger.info("=" * 50)

   
    logger.info("[0/5] Updater — checking for fingerprint updates...")
    FingerprintUpdater().check_and_update()

    logger.info("[1/5] Loading plugins...")
    plugins = load_plugins()

  
    logger.info("[2/5] Surveyor — scanning local network...")
    surveyor = SurveyorScanner(subnet=subnet)
    devices  = surveyor.scan()

    logger.info("[3/5] Grabber — banner grabbing and fingerprinting...")
    grabber = BannerGrabber()
    devices = grabber.enrich_all(devices)

    # Fills in manufacturer/type for devices banner grabbing
    # couldn't identify (phones, IoT, generic devices)
    logger.info("[3b/5] MAC OUI lookup — enriching unknown devices...")
    mac_lookup = MacLookup()
    devices    = mac_lookup.enrich_devices(devices)

    # Plugins get a pass on still-unknown devices
    if plugins:
        logger.info(f"  Running {len(plugins)} plugin(s) on unknown devices...")
        for device in devices:
            for open_port in device.ports:
                if open_port.device_type != "unknown":
                    continue
                for plugin in plugins:
                    try:
                        match = plugin.fingerprint(open_port.port, open_port.banner)
                        if match:
                            open_port.device_type  = match.device_type
                            open_port.manufacturer = match.manufacturer
                            logger.debug(
                                f"  [{plugin.name}] identified "
                                f"{device.ip}:{open_port.port} as "
                                f"{match.manufacturer} {match.device_type}"
                            )
                            break
                    except Exception as e:
                        logger.warning(f"  Plugin {plugin.name} error: {e}")

    # Try NAT-PMP first (no API key, LAN only)
    # Fall back to ipify.org (requires internet)
    logger.info("[4/5] WAN IP detection...")
    wan_ip = _get_wan_ip()
    if wan_ip:
        logger.info(f"  WAN IP: {wan_ip}")
    else:
        logger.warning(
            "  WAN IP not detected — external verification will be skipped. "
            "Mappings will still be flagged."
        )

    result = ScanResult(
        timestamp=datetime.utcnow(),
        subnet=surveyor.subnet,
        wan_ip=wan_ip or "",
        devices=devices,
    )


    # Handles: ONVIF → UPnP → Correlation → Verification → Scoring
    logger.info("[5/5] Analysis engine...")
    engine = LogicEngine(plugins=plugins)
    result = engine.analyse(result)

    # ── Step 6: Plugin on_scan_complete hooks ──────────────
    for plugin in plugins:
        try:
            plugin.on_scan_complete(result)
        except Exception as e:
            logger.warning(f"Plugin {plugin.name} on_scan_complete error: {e}")

    logger.info("=" * 50)
    logger.info(
        f"Scan complete:\n"
        f"  Devices found:       {len(result.devices)}\n"
        f"  Router mappings:     {len(result.mappings)}\n"
        f"  Exposure findings:   {len(result.exposure_findings)}\n"
        f"  Internal findings:   {len(result.device_findings)}\n"
        f"  UPnP leaks:          {len(result.upnp_leaks)}\n"
        f"  Plugins active:      {len(plugins)}\n"
        f"  WAN IP known:        {'Yes' if result.wan_ip else 'No'}"
    )
    logger.info("=" * 50)

    return result


def _get_wan_ip() -> str:
    """
    Detect public WAN IP address.
    1. Try NAT-PMP (LAN only, no API key needed)
    2. Fall back to api.ipify.org (requires internet)
    Returns empty string if neither works.
    """
    # Try NAT-PMP first
    try:
        nat = NatPmpScanner()
        ip  = nat.get_wan_ip()
        if ip:
            logger.debug(f"WAN IP via NAT-PMP: {ip}")
            return ip
    except Exception as e:
        logger.debug(f"NAT-PMP failed: {e}")

    # Fall back to ipify
    try:
        response = requests.get(
            "https://api.ipify.org?format=json", timeout=5
        )
        ip = response.json().get("ip", "")
        if ip:
            logger.debug(f"WAN IP via ipify: {ip}")
            return ip
    except Exception as e:
        logger.debug(f"ipify failed: {e}")

    return ""