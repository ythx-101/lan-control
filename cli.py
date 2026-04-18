#!/usr/bin/env python3
"""
Router Control CLI
Command-line interface for router discovery and device control.
"""
import argparse
import json
import os
import sys
import subprocess
from pathlib import Path

# Add parent to path for registry import
sys.path.insert(0, str(Path(__file__).parent))
import registry

SCRIPT_DIR = Path(__file__).parent / "scripts"
STATE_FILE = Path.home() / ".lan-control" / "state.json"


def run_script(script_name: str, *args) -> subprocess.CompletedProcess:
    """Run a shell script with args."""
    script_path = SCRIPT_DIR / script_name
    cmd = [str(script_path)] + list(args)
    return subprocess.run(cmd, capture_output=False)


def cmd_discover(args):
    """Discover router and all LAN devices."""
    return run_script("discover.sh")


def cmd_connect(args):
    """Connect to router via SSH."""
    password = args.password if hasattr(args, 'password') else None
    if password:
        return run_script("connect.sh", password)
    return run_script("connect.sh")


def cmd_devices(args):
    """List all discovered LAN devices."""
    return run_script("devices.sh")


def cmd_supported(args):
    """List all supported device types from registry."""
    supported = registry.list_supported()
    
    print("=== Supported Devices ===\n")
    for dtype, devices in sorted(supported.items()):
        print(f"## {dtype}")
        for d in devices:
            print(f"  - {d['name']} ({d['vendor']}) - {d['protocol']}")
        print()


def cmd_commands(args):
    """Show commands for a specific device."""
    if not args.device:
        print("Error: device key required", file=sys.stderr)
        print("Use: cli.py supported to see available devices", file=sys.stderr)
        sys.exit(1)
    
    commands = registry.get_commands(args.device)
    if not commands:
        print(f"Unknown device: {args.device}", file=sys.stderr)
        print("Use: cli.py supported to see available devices", file=sys.stderr)
        sys.exit(1)
    
    device = registry.get_device(args.device)
    print(f"# {device['name']} ({device['vendor']})")
    print(f"Protocol: {device['protocol']}")
    print(f"Connection: {device['connection'].get('method', 'unknown')}:{device['connection'].get('port', 'N/A')}")
    print()
    print("## Commands:")
    for cmd_name, cmd_spec in commands.items():
        desc = cmd_spec.get('description', '')
        params = cmd_spec.get('params', {})
        print(f"  {cmd_name}")
        if desc:
            print(f"    {desc}")
        if params:
            print(f"    Params: {params}")


def _resolve_ip_from_state(device_key, device_type):
    """Look up a device's IP in ~/.lan-control/state.json (written by `devices`)."""
    if not STATE_FILE.exists():
        return None
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except (OSError, ValueError):
        return None
    needle = device_key.replace("-", "")
    for d in state.get("devices", []):
        if d.get("type") == device_type:
            return d.get("ip")
        if d.get("hostname", "").lower().find(needle) >= 0:
            return d.get("ip")
    return None


def cmd_control(args):
    """Control a device."""
    import drivers

    device = registry.get_device(args.device)
    if not device:
        print(f"Unknown device: {args.device}", file=sys.stderr)
        print("Use: cli.py supported  to see available devices", file=sys.stderr)
        sys.exit(1)

    # Driver-private: stable key used to scope secrets and per-device state
    device["_key"] = args.device

    # Find the IP we should talk to.
    # 1) device's own state/discovery entry
    # 2) if the profile declares `bridge: <key>`, fall back to the bridge's IP
    #    (e.g. an IR-only AC routed through a BroadLink RM4)
    if "ip" not in device:
        ip = _resolve_ip_from_state(args.device, device.get("type"))
        if not ip and device.get("bridge"):
            bridge_key = device["bridge"]
            bridge = registry.get_device(bridge_key)
            if bridge:
                ip = bridge.get("ip") or _resolve_ip_from_state(bridge_key, bridge.get("type"))
                if ip:
                    print(f"ℹ️  routing {args.device} via bridge {bridge_key} @ {ip}",
                          file=sys.stderr)
        if ip:
            device["ip"] = ip

    result = drivers.execute(device, args.cmd_name, args.params if hasattr(args, 'params') else [])

    # JSON to stdout (agent-friendly)
    print(json.dumps(result, indent=2))

    # Human summary to stderr
    if result.get("ok"):
        output = result.get("output", "")
        if output:
            print(output, file=sys.stderr)
        print(f"✅ {args.device} → {args.cmd_name}", file=sys.stderr)
    else:
        print(f"❌ {result.get('error', 'unknown error')}", file=sys.stderr)
        sys.exit(1)


def cmd_health(args):
    """Run health check."""
    return run_script("health.sh")


def cmd_ping(args):
    """Ping a device."""
    if not args.target:
        print("Error: target required", file=sys.stderr)
        print("Usage: cli.py ping <ip|hostname>", file=sys.stderr)
        sys.exit(1)
    return run_script("ping.sh", args.target)


def main():
    parser = argparse.ArgumentParser(
        description="Router Control - Universal home network discovery and device control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cli.py discover                            # Discover router and LAN devices
  cli.py devices                             # List discovered devices
  cli.py supported                           # List supported device types
  cli.py commands lg-webos                   # Show commands for LG webOS TV
  cli.py control openwrt dhcp_leases         # Control a device
  cli.py control android-tv-box reboot       # Reboot Android TV box
  cli.py health                              # Health check
  cli.py ping 192.168.1.100                  # Ping a device
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # discover
    p_discover = subparsers.add_parser("discover", help="Discover router and LAN topology")
    
    # connect
    p_connect = subparsers.add_parser("connect", help="Connect to router via SSH")
    p_connect.add_argument("password", nargs="?", help="Router SSH password (optional)")
    
    # devices
    p_devices = subparsers.add_parser("devices", help="List all LAN devices")
    
    # supported
    p_supported = subparsers.add_parser("supported", help="List supported device types")
    
    # commands
    p_commands = subparsers.add_parser("commands", help="Show device commands")
    p_commands.add_argument("device", nargs="?", help="Device key (e.g., lg-webos)")
    
    # control
    p_control = subparsers.add_parser("control", help="Control a device")
    p_control.add_argument("device", help="Device to control")
    p_control.add_argument("cmd_name", help="Command to send")
    p_control.add_argument("params", nargs="*", help="Command parameters")
    
    # health
    p_health = subparsers.add_parser("health", help="Router health check")
    
    # ping
    p_ping = subparsers.add_parser("ping", help="Ping a device")
    p_ping.add_argument("target", help="IP address or hostname")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Route to handler
    commands = {
        "discover": cmd_discover,
        "connect": cmd_connect,
        "devices": cmd_devices,
        "supported": cmd_supported,
        "commands": cmd_commands,
        "control": cmd_control,
        "health": cmd_health,
        "ping": cmd_ping,
    }
    
    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
