# lan-control

> **Turn your home router into a universal device control hub.**  
> Zero config · Auto-discover · YAML device profiles · Community-driven · Local-first

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg?style=flat-square)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green.svg?style=flat-square)](https://www.python.org)
[![OpenClaw Skill](https://img.shields.io/badge/OpenClaw-Skill-blue.svg?style=flat-square)](https://github.com/openclaw/openclaw)

A CLI tool that discovers and controls every device on your home network — LG TV, BroadLink IR, Android boxes, cameras, and [many more](#supported-devices) — powered by multi-method LAN scanning and community-maintained YAML device profiles.

---

## Table of Contents

- [Highlights](#highlights)
- [Quick Start](#quick-start)
- [Supported Devices](#supported-devices)
- [Built-in Commands](#built-in-commands)
- [Add Your Device](#add-your-device)
- [How It Works](#how-it-works)
- [Anti-patterns We Handle](#anti-patterns-we-handle)
- [License](#license)

---

## Highlights

- **Universal** — Not tied to any router brand or SSH. Works with OpenWrt, GL.iNet, ASUS Merlin, TP-Link, Xiaomi, Ubiquiti — and even without router access.
- **Multi-method discovery** — SSH into router (best) → ARP scan → nmap → mDNS/UPnP. Falls back automatically.
- **Zero config** — Auto-discovers your router and devices. No manual IP entry.
- **YAML-driven** — Each device type is a `.yaml` file. Adding support = adding a file. No code changes.
- **Community-driven** — MAC prefix + hostname pattern matching. Drop a YAML, submit a PR, done.
- **Local-first** — Runs on your Mac/Linux. No cloud, no VPS, no account. Your router, your data.
- **Agent-ready** — All output is structured JSON (stdout). Human summaries go to stderr.

## Quick Start

```bash
git clone https://github.com/ythx-101/lan-control.git
cd lan-control
pip install -r requirements.txt
```

```bash
python3 cli.py discover                    # Find your router
python3 cli.py connect                     # SSH into router (auto key/password)
python3 cli.py devices                     # List all LAN devices
python3 cli.py commands lg-webos           # Show available commands
python3 cli.py control openwrt uptime      # Execute command on device
python3 cli.py health                      # Router health check
```

Example output:

```
$ python3 cli.py discover
🔍 Default gateway: 192.168.1.1
🔑 SSH: open (SSH-2.0-dropbear)
✅ Router: GL-AXT1800 (OpenWrt 23.05)

$ python3 cli.py devices
📱 4 devices found:
  📺 192.168.1.100  LG webOS TV          ssap
  🎛️ 192.168.1.101  BroadLink RM4        broadlink
  📷 192.168.1.102  Reolink Camera       http
  📦 192.168.1.103  Android TV Box       adb

$ python3 cli.py commands lg-webos
  power_off     Power off
  volume_up     Volume +
  launch_app    Launch app by id  [youtube, netflix, ...]
  set_volume    Set volume (0-100)
  screenshot    Capture screen to local file
  yt_play       Play YouTube video by id
  button        Send a single remote button (UP/DOWN/ENTER/...)
  ...39 commands total
```

## Supported Devices

| Type | Devices | Protocol | Control | Status |
|------|---------|----------|---------|--------|
| **Router** | OpenWrt, GL.iNet, ASUS Merlin, TP-Link, Xiaomi, Ubiquiti | SSH/HTTP API | `ssh` driver | ✅ Verified |
| **TV** | LG webOS | WebSocket (SSAP) | `ssap` driver | ✅ Verified |
| **TV** | Samsung Tizen, Roku | HTTP | planned | 📝 Planned |
| **IR Remote** | BroadLink RM4 / RM Mini | UDP (AES-128) | `broadlink` driver | ✅ Verified |
| **Android Box** | H616/H618/S905/RK3566 | ADB/SSH | `adb` driver | ✅ Verified |
| **E-ink** | ESP32 displays (Waveshare, LilyGo, TRMNL) | HTTP | `http` driver | ✅ Profile |
| **Speaker** | Google Nest, Amazon Echo | Cast/HTTP | planned | 📝 Planned |
| **Camera** | Reolink, Hikvision | HTTP | `http` driver | 📝 Planned |
| **AC** | Generic IR (bridged via BroadLink) | IR Bridge | `broadlink` driver | ✅ Profile |
| **IoT** | ESP/Tuya, Tasmota | HTTP/MQTT | `http` driver | 📝 Planned |

> **✅ Verified** = tested on real hardware with working driver. **✅ Profile** = YAML profile exists, driver in progress. **📝 Planned** = PRs welcome.

## Built-in Commands

| Command | Description |
|---------|-------------|
| `discover` | Auto-detect router (gateway → SSH → HTTP → ARP fallback) |
| `connect [password]` | SSH into router (key → password → defaults, auto-fallback) |
| `devices` | Scan LAN devices (SSH DHCP → ARP fallback) |
| `supported` | List all supported device types from YAML profiles |
| `commands <device>` | List available commands for a device type |
| `control <device> <cmd> [params]` | **Execute command on a device** (SSH/ADB/HTTP) |
| `health` | Router health (memory, WireGuard, DNS, device ping) |
| `ping <ip\|hostname>` | Check if a device is online |

## Add Your Device

Your device isn't listed? **5 minutes:**

### 1. Create a YAML file

```yaml
# devices/tv/my-smart-tv.yaml
device:
  name: "My Smart TV"
  type: tv
  vendor: MyBrand
  protocol: http

discovery:
  mac_prefixes:
    - "aa:bb:cc"           # First 3 bytes of MAC
  hostname_patterns:
    - "(?i)mysmartv"       # Regex for DHCP hostname

connection:
  method: http
  port: 8080

commands:
  power_off:
    description: "Power off"
    action: "POST /api/power/off"
  volume_up:
    description: "Volume +"
    action: "POST /api/volume/up"
```

### 2. Test

```bash
python3 cli.py supported    # Your device should appear
```

### 3. Submit PR

That's it. The registry auto-scans all YAML files in `devices/`.

## How It Works

### Discovery Methods (auto-fallback)

| Method | Needs Router SSH? | What you get | Best for |
|--------|:-:|-------------|----------|
| **SSH DHCP scan** | ✅ | All devices with MAC + hostname + IP | OpenWrt, GL.iNet, ASUS Merlin |
| **ARP table** | ❌ | Devices your machine has talked to | Any network, no router access |
| **nmap scan** | ❌ | All active IPs + open ports + OS hints | Deep scan, any network |
| **mDNS/Bonjour** | ❌ | Devices advertising services | Apple TV, Chromecast, printers |
| **UPnP/SSDP** | ❌ | Devices with UPnP enabled | Smart TVs, speakers, cameras |
| **Router HTTP API** | ❌ SSH, ✅ Web | Device list via admin API | Xiaomi, Huawei, TP-Link (no SSH) |

> **No SSH? No problem.** lan-control tries SSH first (most complete data), then falls back to local network scanning. You always get *something*.

### Architecture

```
lan-control
   │
   ├── SSH → router DHCP table     (best: full MAC + hostname)
   ├── ARP → local ARP cache       (good: MAC + IP)
   ├── nmap → subnet scan           (good: IP + ports + OS)
   ├── mDNS → service discovery     (partial: advertising devices)
   └── UPnP → SSDP broadcast       (partial: UPnP devices)
   │
   ▼
MAC prefix + hostname → match devices/*.yaml
   │
   ▼
Identified devices → native protocol commands
   📺 LG TV      → WebSocket (SSAP)
   🎛️ BroadLink  → UDP (AES-128-CBC)
   ❄️ IR AC      → bridged through BroadLink
   📷 Camera     → HTTP API
   📦 Android    → ADB
```

```
devices/             ← Community contributes HERE
  router/            OpenWrt, GL.iNet, ASUS, TP-Link
  tv/                LG webOS, Samsung Tizen, Roku
  ir-remote/         BroadLink, Tuya IR
  ac/                IR air conditioners (bridged through BroadLink)
  speaker/           Google Nest, Amazon Echo
  camera/            Reolink, Hikvision
  iot/               Android Box, ESP/Tuya, Tasmota
  _schema.yaml       Template for new devices
drivers/             ← Protocol implementations
  ssh.py             OpenWrt / Linux shells
  adb.py             Android TV boxes
  http.py            REST / webhook devices
  ssap.py            LG webOS over WebSocket (pair → store key)
  broadlink.py       BroadLink RM4 UDP (AES-128-CBC)
registry.py          ← Auto-scans devices/
cli.py               ← CLI entry point
scripts/             ← Shell scripts (discover, connect, health)

~/.lan-control/      ← User-local state (never committed)
  state.json         Discovered devices from last `devices` run
  secrets.yaml       LG webOS client-keys, chmod 0600
  ir_codes/          Learned IR codes, one JSON per device
```

## Anti-patterns We Handle

| Trap | What happens | Solution |
|------|-------------|----------|
| Clash/Surge fake IP | Gateway shows 198.18.0.1 (TUN) | Auto-detect fake-ip range, find real gateway |
| ISP port blocking | WireGuard on 51820 silently fails | Documented diagnosis + port change |
| Double NAT | Router WAN is private 192.168.x.x | Detection + bridge mode guidance |
| Router OOM | Services crash with <512MB RAM | Swap setup on external storage |
| Dropbear SSH | Different auth flow than OpenSSH | Multi-method auth (key → password → defaults) |

## License

[Apache-2.0](LICENSE)
## Documentation

- [Contributing Guide](references/contributing.md)
- [Device Schema](references/device-schema.md)
- [Router Profiles](references/router-profiles.md)
- [Troubleshooting](references/troubleshooting.md)

