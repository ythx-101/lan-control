"""
Protocol drivers for device control.
Each driver implements execute(device_config, command_name, command_spec, params) -> dict.
"""
import sys
from typing import Dict, Any, Optional

# Registry of protocol → driver module
_drivers: Dict[str, Any] = {}


def get_driver(protocol: str):
    """Get driver module for a protocol. Lazy-loads on first access."""
    if protocol in _drivers:
        return _drivers[protocol]

    if protocol in ("ssh",):
        from drivers import ssh
        _drivers["ssh"] = ssh
        return ssh
    elif protocol in ("adb",):
        from drivers import adb
        _drivers["adb"] = adb
        return adb
    elif protocol in ("http", "https"):
        from drivers import http
        _drivers[protocol] = http
        return http
    elif protocol in ("ssap", "websocket"):
        from drivers import ssap
        _drivers[protocol] = ssap
        return ssap
    elif protocol in ("broadlink", "udp"):
        from drivers import broadlink
        _drivers[protocol] = broadlink
        return broadlink
    else:
        return None


def execute(device_config: dict, command_name: str, params: list) -> dict:
    """
    Execute a command on a device.
    Returns {"ok": True, "output": ...} or {"ok": False, "error": ...}.
    """
    protocol = device_config.get("protocol", "unknown")
    driver = get_driver(protocol)

    if driver is None:
        return {"ok": False, "error": f"Protocol '{protocol}' not yet supported. Supported: ssh, adb, http, ssap, broadlink"}

    commands = device_config.get("commands", {})
    cmd_spec = commands.get(command_name)
    if cmd_spec is None:
        available = ", ".join(commands.keys()) or "(none)"
        return {"ok": False, "error": f"Unknown command '{command_name}'. Available: {available}"}

    try:
        return driver.execute(device_config, command_name, cmd_spec, params)
    except Exception as e:
        return {"ok": False, "error": str(e)}
