"""
models.py
Shared data types for Muhafiz LAN scanner.
Architecture: Discovery → Device Intelligence → Router Intelligence
              → Exposure Correlation → External Verification → Risk Engine
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class OpenPort:
    port:         int
    protocol:     str          # tcp / udp
    service:      str          # e.g. "rtsp", "http", "telnet"
    banner:       str          #raw banner grabbed from the port
    device_type:  str          # e.g. "ip_camera", "printer", "nas"
    manufacturer: str          # e.g. "Axis Communications"

@dataclass
class Device:
    ip:           str
    mac:          str
    hostname:     str
    ports:        list[OpenPort] = field(default_factory=list)
    is_camera:    bool = False  # confirmed via ONVIF or banner
    onvif_info:   dict = field(default_factory=dict)  # ONVIF metadata if found

@dataclass
class PortMapping:
    internal_ip:    str
    internal_port:  int
    external_port:  int
    protocol:       str        # TCP / UDP
    description:    str
    source:         str        # "upnp" / "nat_pmp"
    lease_duration: int        # seconds, 0 = permanent


@dataclass
class UPnPLeak:
    internal_ip:    str
    internal_port:  int
    external_port:  int
    protocol:       str
    description:    str
    lease_duration: int
    source:         str = "upnp"    # "upnp" or "nat_pmp"



#Only produced when a device has a confirmed port mapping

@dataclass
class ExternalVerification:
    wan_ip:          str
    external_port:   int
    protocol:        str           # "rtsp" / "http" / "tcp"
    reachable:       bool          # True = connection succeeded
    banner:          str = ""      # response received if any
    verified_at:     Optional[datetime] = None


# Produced when device + mapping + (optionally) verification align

@dataclass
class ExposureFinding:
    device:          Device
    mapping:         PortMapping           # confirmed router mapping
    verification:    Optional[ExternalVerification] = None  # None if not yet verified
    risk_score:      int = 0              # 1-10
    severity:        str = "LOW"          # LOW / MEDIUM / HIGH / CRITICAL
    confidence:      int = 0              # 0-100%
    reasons:         list[str] = field(default_factory=list)
    remediation:     list[str] = field(default_factory=list)

@dataclass
class DeviceRiskFinding:
    device:          Device
    risk_score:      int
    severity:        str
    confidence:      int           # always lower without mapping confirmation
    reasons:         list[str] = field(default_factory=list)
    remediation:     list[str] = field(default_factory=list)


#one complete scan consists of one object of ScanResult
@dataclass
class ScanResult:
    timestamp:        datetime
    subnet:           str
    wan_ip:           str = "" 
    devices:          list[Device]              = field(default_factory=list)
    mappings:         list[PortMapping]         = field(default_factory=list)
    upnp_leaks:       list[UPnPLeak]            = field(default_factory=list)
    exposure_findings: list[ExposureFinding]    = field(default_factory=list)
    device_findings:  list[DeviceRiskFinding]   = field(default_factory=list)


#data to be sent to community api

@dataclass
class ContributionPayload:
    port:            int
    banner_snippet:  str
    device_type:     str
    manufacturer:    str
    risk_score:      int
    client_version:  str
    contributed_at:  datetime = field(default_factory=datetime.utcnow)