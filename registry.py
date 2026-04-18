#!/usr/bin/env python3
"""
Device Registry - Auto-scan devices/ directory and build device configuration registry.
Community contributors simply add YAML files to devices/<type>/, they are auto-detected.
"""
import os
import re
import yaml
from pathlib import Path
from typing import Optional, List, Dict, Any

REGISTRY_DIR = Path(__file__).parent
DEVICES_DIR = REGISTRY_DIR / "devices"

# Cache for loaded device configs
_device_cache: Dict[str, Any] = {}


def _scan_yaml_files() -> List[Path]:
    """Scan devices/ directory for all YAML files, excluding _schema.yaml."""
    yaml_files = []
    if not DEVICES_DIR.exists():
        return yaml_files
    
    for pattern in ["**/*.yaml", "**/*.yml"]:
        yaml_files.extend(DEVICES_DIR.glob(pattern))
    
    # Filter out schema files and sort
    return sorted([f for f in yaml_files if "_schema" not in f.name])


def load_device_configs() -> Dict[str, Any]:
    """Load all device YAML configs into cache."""
    global _device_cache
    if _device_cache:
        return _device_cache
    
    configs = {}
    for yaml_file in _scan_yaml_files():
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data or 'device' not in data:
                continue
            
            device_type = data['device'].get('type', 'unknown')
            device_name = data['device'].get('name', yaml_file.stem)
            
            # Store by filename (without extension) as key
            key = yaml_file.stem
            configs[key] = {
                'file': str(yaml_file.relative_to(REGISTRY_DIR)),
                'type': device_type,
                'name': device_name,
                'vendor': data['device'].get('vendor', 'unknown'),
                'protocol': data['device'].get('protocol', 'unknown'),
                'discovery': data.get('discovery', {}),
                'connection': data.get('connection', {}),
                'commands': data.get('commands', {}),
                # Bridge: for devices that don't sit on the network themselves
                # (e.g. an IR-only AC bridged through a BroadLink RM4).
                'bridge': data.get('bridge'),
            }
        except Exception as e:
            print(f"Warning: Failed to load {yaml_file}: {e}", file=__import__('sys').stderr)
    
    _device_cache = configs
    return configs


def identify(mac: str, hostname: str = "") -> Optional[Dict[str, Any]]:
    """
    Identify a device by MAC address and hostname.
    Returns matched device config or None.
    """
    configs = load_device_configs()
    mac_lower = mac.lower()
    hostname_lower = hostname.lower() if hostname else ""
    
    for key, config in configs.items():
        discovery = config.get('discovery', {})
        
        # Check MAC prefixes
        mac_prefixes = discovery.get('mac_prefixes', [])
        for prefix in mac_prefixes:
            if mac_lower.startswith(prefix.lower()):
                return {**config, 'match_type': 'mac', 'match_value': prefix}
        
        # Check hostname patterns
        hostname_patterns = discovery.get('hostname_patterns', [])
        for pattern in hostname_patterns:
            try:
                if re.search(pattern, hostname_lower):
                    return {**config, 'match_type': 'hostname', 'match_value': pattern}
            except re.error:
                pass
        
        # Check mDNS services
        # (would require network scan, not implemented yet)
        
        # Check SSDP
        # (would require network scan, not implemented yet)
    
    return None


def list_supported() -> List[Dict[str, Any]]:
    """List all supported device types."""
    configs = load_device_configs()
    
    # Group by type
    by_type = {}
    for key, config in configs.items():
        dtype = config['type']
        if dtype not in by_type:
            by_type[dtype] = []
        by_type[dtype].append({
            'key': key,
            'name': config['name'],
            'vendor': config['vendor'],
            'protocol': config['protocol'],
        })
    
    return by_type


def get_commands(device_key: str) -> Dict[str, Any]:
    """Get commands for a specific device."""
    configs = load_device_configs()
    device = configs.get(device_key)
    
    if not device:
        return {}
    
    return device.get('commands', {})


def get_device(device_key: str) -> Optional[Dict[str, Any]]:
    """Get full device config by key."""
    configs = load_device_configs()
    return configs.get(device_key)


def list_device_keys() -> List[str]:
    """List all device keys."""
    configs = load_device_configs()
    return list(configs.keys())


if __name__ == '__main__':
    import json
    
    # Demo: list all supported devices
    print("=== Supported Devices ===")
    supported = list_supported()
    print(json.dumps(supported, indent=2))
    
    print("\n=== Identify Example ===")
    # Example: identify an LG TV by MAC
    result = identify(mac="4c:ba:d7123456", hostname="LGwebOSTV")
    print(json.dumps(result, indent=2))
