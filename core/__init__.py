"""
core/__init__.py
Wires together the three scanner modules, analysis engine,
fingerprint updater, and plugin system into one call.
"""

import logging
from datetime import datetime

from core.ghost import GhostScanner
from core.surveyor import SurveyorScanner
from core.grabber import BannerGrabber
from core.models import ScanResult
from analysis.updater import FingerprintUpdater
from analysis.engine import LogicEngine
from plugins import load_plugins

logger = logging.getLogger(__name__)


def run_scan(subnet: str = None) -> ScanResult:
    """
    Run a full Muhafiz scan including analysis.
    Returns a fully enriched ScanResult with correlations,
    UPnP leaks, and risk scores already populated.

    Steps:
    0. Auto-update fingerprint database
    1. Load plugins
    2. Get WAN IP and query Shodan
    3. ARP sweep the local subnet
    4. Banner grab + plugin fingerprinting
    5. Analysis — UPnP scan + correlation + scoring
       (on_critical_found fired here per finding)
    6. on_scan_complete fired on all plugins
    7. Return complete ScanResult
    """

    logger.info("=" * 50)
    logger.info("Muhafiz scan starting...")
    logger.info("=" * 50)
    logger.info("[0/5] Updater — checking for fingerprint updates...")
    FingerprintUpdater().check_and_update()
    logger.info("[1/5] Loading plugins...")
    plugins = load_plugins()
    logger.info("[2/5] Ghost — querying Shodan...")
    ghost         = GhostScanner()
    wan_ip        = ghost.get_wan_ip()
    exposed_ports = ghost.scan(wan_ip)
    logger.info("[3/5] Surveyor — scanning local network...")
    surveyor = SurveyorScanner(subnet=subnet)
    devices  = surveyor.scan()
    logger.info("[4/5] Grabber — fingerprinting devices...")
    grabber = BannerGrabber()
    devices = grabber.enrich_all(devices)

    if plugins:
        logger.info(f"Running {len(plugins)} plugin(s) on unknown devices...")
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
                                f"{match.manufacturer} {match.device_type} "
                                f"(confidence {match.confidence:.0%})"
                            )
                            break
                    except Exception as e:
                        logger.warning(f"Plugin {plugin.name} fingerprint error: {e}")

    logger.info("[5/5] Analysis engine — correlating findings...")
    result = ScanResult(
        timestamp=datetime.utcnow(),
        wan_ip=wan_ip,
        subnet=surveyor.subnet,
        devices=devices,
        exposed_ports=exposed_ports,
    )

    engine = LogicEngine(plugins=plugins)
    result = engine.analyse(result)
    for plugin in plugins:
        try:
            plugin.on_scan_complete(result)
        except Exception as e:
            logger.warning(f"Plugin {plugin.name} on_scan_complete error: {e}")

    logger.info("=" * 50)
    logger.info(
        f"Scan complete — "
        f"{len(result.devices)} device(s), "
        f"{len(result.exposed_ports)} WAN port(s), "
        f"{len(result.correlations)} critical finding(s), "
        f"{len(result.upnp_leaks)} UPnP leak(s), "
        f"{len(plugins)} plugin(s) active"
    )
    logger.info("=" * 50)

    return result