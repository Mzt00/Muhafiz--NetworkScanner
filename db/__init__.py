"""
db/__init__.py
Local database package.
Exports the DeviceRegistry for use across the app.
"""

from db.registry import DeviceRegistry

__all__ = ["DeviceRegistry"]