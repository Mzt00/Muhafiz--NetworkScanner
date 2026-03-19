"""
api/validator.py
Server-side payload validation.
"""

import re


# Allowed device types
VALID_DEVICE_TYPES = {
    "ip_camera", "dvr", "nas", "router", "smart_plug",
    "smart_hub", "media_server", "printer", "voip_phone",
    "gaming_console", "phone", "laptop", "unknown",
}

# IP address pattern — must not appear in any field
IP_PATTERN = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")


def validate_payload(data: dict) -> tuple[bool, str]:
    """
    Validate a contribution payload server-side.
    Returns (True, "") if valid, (False, reason) if not.
    """

    # Port range
    port = data.get("port", 0)
    if not 1 <= port <= 65535:
        return False, f"Invalid port: {port}"

    # Risk score range
    risk = data.get("risk_score", 0)
    if not 1 <= risk <= 10:
        return False, f"Invalid risk score: {risk}"

    # Banner length
    banner = data.get("banner_snippet", "")
    if len(banner) > 120:
        return False, f"Banner too long: {len(banner)} chars (max 120)"

    # No IPs anywhere in the payload
    for field in ["banner_snippet", "device_type", "manufacturer"]:
        value = str(data.get(field, ""))
        if IP_PATTERN.search(value):
            return False, f"Field '{field}' contains an IP address — rejected."

    # Device type must be from allowed list
    device_type = data.get("device_type", "unknown")
    if device_type not in VALID_DEVICE_TYPES:
        return False, f"Unknown device_type: {device_type}"

    # UUID must be present
    if not data.get("uuid"):
        return False, "Missing UUID."

    # Client version must be present
    if not data.get("client_version"):
        return False, "Missing client_version."

    return True, ""