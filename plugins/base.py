"""
plugins/base.py
Abstract base class for Muhafiz plugins.
Every plugin must inherit from BasePlugin and implement
the fingerprint() method at minimum.

To create a plugin:
1. Create a new .py file in the plugins/ folder
2. Inherit from BasePlugin
3. Implement fingerprint()
4. Optionally implement on_scan_complete() and on_critical_found()
5. Muhafiz auto-discovers and loads it on next startup

Example:
    from plugins.base import BasePlugin, DeviceMatch

    class MyPlugin(BasePlugin):
        name = "My Camera Plugin"
        version = "0.1.0"
        author = "Your Name"

        def fingerprint(self, port: int, banner: str) -> DeviceMatch | None:
            if port == 8888 and "MyCam" in banner:
                return DeviceMatch(
                    device_type="ip_camera",
                    manufacturer="MyCam Inc.",
                    risk_base=8,
                    confidence=0.95,
                )
            return None
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from core.models import ScanResult, CriticalCorrelation



@dataclass
class DeviceMatch:
    device_type:  str
    manufacturer: str
    risk_base:    int           # 1-10
    confidence:   float = 1.0  # 0.0 to 1.0 — how confident the plugin is
    notes:        str   = ""

class BasePlugin(ABC):

    # Plugin metadata — override in subclass
    name:        str = "Unnamed Plugin"
    version:     str = "0.1.0"
    author:      str = "Unknown"
    description: str = ""


    @abstractmethod
    def fingerprint(self, port: int, banner: str) -> Optional[DeviceMatch]:
        """
        Try to identify a device from its port number and banner string.

        Args:
            port:   The open port number (e.g. 554, 8080)
            banner: The raw banner grabbed from that port

        Returns:
            DeviceMatch if this plugin recognises the device,
            None if it doesn't match.
        """
        pass

    def on_scan_complete(self, result: ScanResult) -> None:
        """
        Called after a full scan completes.
        Override to add custom post-scan logic — e.g. sending
        a notification, writing to a custom database, or
        triggering an external webhook.

        Args:
            result: The complete ScanResult from the scan
        """
        pass

    def on_critical_found(self, correlation: CriticalCorrelation) -> None:
        """
        Called immediately when a critical correlation is found
        during analysis — before the full scan completes.
        Override to trigger real-time alerts e.g. push
        notifications, Slack messages, or SMS.

        Args:
            correlation: The CriticalCorrelation that was found
        """
        pass


    def __repr__(self) -> str:
        return f"<Plugin: {self.name} v{self.version} by {self.author}>"