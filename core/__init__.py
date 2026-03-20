"""
core/__init__.py
Wires together the three scanner modules, runs the
fingerprint updater, and fires plugin hooks.
"""

import logging
from datetime import datetime

from core.ghost import GhostScanner
from core.surveyor import SurveyorScanner
from core.grabber import BannerGrabber
from core.models import ScanResult
from analysis.updater import FingerprintUpdater
from plugins import load_plugins

logger = logging.getLogger(__name__)


def run_scan(subnet: str = None) -> ScanResult:
    """
    Run a full Muhafiz scan:
    0. Auto-update fingerprint database
    1. Load plugins
    2. Get WAN IP and query Shodan
    3. ARP sweep the local subnet
    4. Banner grab and fingerprint each device
       (plugins get a chance to identify devices too)
    5. Fire on_scan_complete hooks on all plugins
    6. Return a complete ScanResult
    """

    logger.info("=" * 50)
    logger.info("Muhafiz scan starting...")
    logger.info("=" * 50)
    logger.info("[0/4] Updater — checking for fingerprint updates...")
    updater = FingerprintUpdater()
    updater.check_and_update()

    logger.info("[1/4] Loading plugins...")
    plugins = load_plugins()

    logger.info("[2/4] Ghost — querying Shodan...")
    ghost         = GhostScanner()
    wan_ip        = ghost.get_wan_ip()
    exposed_ports = ghost.scan(wan_ip)

    logger.info("[3/4] Surveyor — scanning local network...")
    surveyor = SurveyorScanner(subnet=subnet)
    devices  = surveyor.scan()

    logger.info("[4/4] Grabber — fingerprinting devices...")
    grabber = BannerGrabber()
    devices = grabber.enrich_all(devices)

    # Give plugins a chance to identify any unknown devices
    # the built-in fingerprint DB didn't catch
    if plugins:
        logger.info(f"Running {len(plugins)} plugin(s) on discovered devices...")
        for device in devices:
            for open_port in device.ports:
                if open_port.device_type != "unknown":
                    continue  # already identified — skip

                for plugin in plugins:
                    try:
                        match = plugin.fingerprint(open_port.port, open_port.banner)
                        if match:
                            open_port.device_type  = match.device_type
                            open_port.manufacturer = match.manufacturer
                            logger.debug(
                                f"  [{plugin.name}] identified "
                                f"{device.ip}:{open_port.port} as "
                                f"{match.manufacturer} {match.device_type} "
                                f"(confidence {match.confidence:.0%})"
                            )
                            break  # first matching plugin wins
                    except Exception as e:
                        logger.warning(f"  Plugin {plugin.name} error: {e}")

    result = ScanResult(
        timestamp=datetime.utcnow(),
        wan_ip=wan_ip,
        subnet=surveyor.subnet,
        devices=devices,
        exposed_ports=exposed_ports,
    )

    for plugin in plugins:
        try:
            plugin.on_scan_complete(result)
        except Exception as e:
            logger.warning(f"Plugin {plugin.name} on_scan_complete error: {e}")

    logger.info("=" * 50)
    logger.info(
        f"Scan complete — "
        f"{len(devices)} device(s) found, "
        f"{len(exposed_ports)} port(s) exposed on WAN, "
        f"{len(plugins)} plugin(s) active"
    )
    logger.info("=" * 50)

    return result