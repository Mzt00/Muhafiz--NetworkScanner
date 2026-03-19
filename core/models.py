"""
models.py
Shared data types used across all Muhafiz modules.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
@dataclass
class OpenPort:
    port: int
    protocol: str          # tcp / udp
    service: str           # e.g. "rtsp", "http", "telnet"
    banner: str            # raw banner grabbed from the port
    device_type: str       # e.g. "ip_camera", "printer", "nas"
    manufacturer: str      # e.g. "Axis Communications"


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str
    ports: list[OpenPort] = field(default_factory=list)




@dataclass
class ExposedPort: #exposed on shodan
    port: int
    protocol: str
    service: str
    banner: str
    cves: list[str] = field(default_factory=list)   
    last_seen: Optional[datetime] = None




@dataclass
class CriticalCorrelation: #device discoveed both internally and in shodan search
    device: Device
    exposed_port: ExposedPort
    risk_score: int                
    reason: str                    


@dataclass
class UPnPLeak:
    internal_ip: str
    internal_port: int
    external_port: int
    protocol: str
    description: str               # UPnP description string from the router
    lease_duration: int            # seconds remaining, 0 = permanent




@dataclass
class ScanResult: #one full scan is an object of ScanResult
    timestamp: datetime
    wan_ip: str
    subnet: str
    devices: list[Device] = field(default_factory=list)
    exposed_ports: list[ExposedPort] = field(default_factory=list)
    correlations: list[CriticalCorrelation] = field(default_factory=list)
    upnp_leaks: list[UPnPLeak] = field(default_factory=list)


@dataclass
class ContributionPayload: #stripped down record of scan used for maintaining community database
    #doesnt contain user IP address and mac addr
    port: int
    banner_snippet: str            
    device_type: str
    manufacturer: str
    risk_score: int
    shodan_match: bool
    client_version: str
    contributed_at: datetime = field(default_factory=datetime.utcnow)