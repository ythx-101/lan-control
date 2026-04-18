"""
BroadLink UDP protocol driver — RM4 IR/RF remote control.

Zero Python crypto dependency. Prefers the `cryptography` package when
available; falls back to `openssl enc` CLI (works on OpenWrt, aarch64
routers where building pycryptodome is painful).

IR code tables are per-device and kept out of the shared profile YAML:
they live under ~/.lan-control/ir_codes/<device_key>.json so every user
learns their own remote without polluting the repo.
"""
import base64
import json
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

# Broadlink protocol constants — publicly documented, shared by all
# python-broadlink implementations. NOT a per-device secret.
INIT_KEY = bytes.fromhex("097628343fe99e23765c1513accf8b02")
INIT_IV = bytes.fromhex("562e17996d093d28ddb3ba695a2e6f58")

# Device types that use RM4's length-prefixed IR packet format.
RM4_DEVTYPES = {
    0x520c, 0x5213, 0x5218, 0x6026, 0x6184,
    0x610e, 0x610f, 0x62bc, 0x62be, 0x649b, 0x653a,
}

STATE_DIR = Path.home() / ".lan-control"
IR_CODES_DIR = STATE_DIR / "ir_codes"
DEFAULT_TIMEOUT = 5


# ---- crypto: cryptography lib first, openssl CLI fallback ----

def _have_cryptography() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher  # noqa
        return True
    except ImportError:
        return False


def _aes_cbc(mode: str, key: bytes, iv: bytes, data: bytes) -> bytes:
    """mode = 'encrypt' or 'decrypt'. NO padding."""
    if _have_cryptography():
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        worker = cipher.encryptor() if mode == "encrypt" else cipher.decryptor()
        return worker.update(data) + worker.finalize()

    if not shutil.which("openssl"):
        raise RuntimeError(
            "Neither `cryptography` package nor `openssl` CLI found. "
            "Install one: pip install cryptography  (or) apt/opkg install openssl"
        )
    args = ["openssl", "enc", "-aes-128-cbc", "-nopad",
            "-K", key.hex(), "-iv", iv.hex()]
    if mode == "decrypt":
        args.insert(2, "-d")
    p = subprocess.run(args, input=data, capture_output=True, timeout=5)
    if p.returncode != 0:
        raise RuntimeError(f"openssl {mode} failed: {p.stderr.decode(errors='replace')}")
    return p.stdout


# ---- local source address detection ----

def _local_ip_for(peer_ip: str) -> str:
    """Best-effort: source address used to reach peer_ip. No broadcast traffic."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer_ip, 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


# ---- Broadlink session ----

class BroadlinkSession:
    def __init__(self, ip: str, port: int = 80, timeout: int = DEFAULT_TIMEOUT):
        self.host = (ip, port)
        self.mac = bytes(6)
        self.devtype = 0
        self.count = random.randint(0x8000, 0xFFFF)
        self.id = 0
        self.key = INIT_KEY
        self.iv = INIT_IV
        self.timeout = timeout

    def _send_packet(self, ptype: int, payload: bytes) -> bytes:
        self.count = ((self.count + 1) | 0x8000) & 0xFFFF
        pkt = bytearray(0x38)
        pkt[0x00:0x08] = bytes.fromhex("5aa5aa555aa5aa55")
        pkt[0x24:0x26] = self.devtype.to_bytes(2, "little")
        pkt[0x26:0x28] = ptype.to_bytes(2, "little")
        pkt[0x28:0x2A] = self.count.to_bytes(2, "little")
        pkt[0x2A:0x30] = self.mac[::-1]
        pkt[0x30:0x34] = self.id.to_bytes(4, "little")

        p_checksum = (sum(payload) + 0xBEAF) & 0xFFFF
        pkt[0x34:0x36] = p_checksum.to_bytes(2, "little")

        padding = (16 - len(payload) % 16) % 16
        encrypted = _aes_cbc("encrypt", self.key, self.iv, bytes(payload) + bytes(padding))
        pkt.extend(encrypted)

        checksum = (sum(pkt) + 0xBEAF) & 0xFFFF
        pkt[0x20:0x22] = checksum.to_bytes(2, "little")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(bytes(pkt), self.host)
            return sock.recv(2048)
        finally:
            sock.close()

    def discover_and_auth(self) -> None:
        # Unicast discover to the device (no broadcast needed if we know IP)
        src_ip = _local_ip_for(self.host[0])
        parts = src_ip.split(".")
        if len(parts) != 4:
            parts = ["0", "0", "0", "0"]

        disc = bytearray(0x30)
        now = time.localtime()
        disc[0x08] = now.tm_year & 0xFF
        disc[0x09] = (now.tm_year >> 8) & 0xFF
        disc[0x0A] = now.tm_min
        disc[0x0B] = now.tm_hour
        disc[0x0C] = now.tm_year % 100
        disc[0x0D] = now.tm_wday
        disc[0x0E] = now.tm_mday
        disc[0x0F] = now.tm_mon
        for i, p in enumerate(parts):
            try:
                disc[0x18 + i] = int(p) & 0xFF
            except ValueError:
                disc[0x18 + i] = 0
        disc[0x1C:0x1E] = (80).to_bytes(2, "little")
        disc[0x26] = 6  # discover

        checksum = (sum(disc) + 0xBEAF) & 0xFFFF
        disc[0x20:0x22] = checksum.to_bytes(2, "little")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(bytes(disc), self.host)
            resp, _ = sock.recvfrom(2048)
            self.mac = resp[0x3A:0x40]
            self.devtype = int.from_bytes(resp[0x34:0x36], "little")
        except socket.timeout:
            # Device silent to discover — proceed with zero-mac auth
            pass
        finally:
            sock.close()

        # Auth
        payload = bytearray(0x50)
        payload[0x04:0x14] = b"\x31" * 16
        payload[0x1E] = 0x01
        payload[0x2D] = 0x01
        payload[0x30:0x36] = b"Test 1"

        resp = self._send_packet(0x65, payload)
        err = int.from_bytes(resp[0x22:0x24], "little")
        if err != 0:
            raise RuntimeError(f"Broadlink auth error {err}")

        dec = _aes_cbc("decrypt", self.key, self.iv, resp[0x38:])
        self.id = int.from_bytes(dec[0x00:0x04], "little")
        self.key = dec[0x04:0x14]
        # Pick up devtype from auth response if discover was silent
        if not self.devtype:
            self.devtype = int.from_bytes(resp[0x24:0x26], "little")

    def send_ir(self, ir_data: bytes) -> None:
        if self.devtype in RM4_DEVTYPES:
            packet = struct.pack("<HI", len(ir_data) + 4, 0x02) + ir_data
        else:
            packet = struct.pack("<I", 0x02) + ir_data
        resp = self._send_packet(0x6A, packet)
        err = int.from_bytes(resp[0x22:0x24], "little")
        if err != 0:
            raise RuntimeError(f"Broadlink send_ir error {err}")

    def enter_learning(self) -> None:
        payload = bytearray(16)
        payload[0] = 3
        self._send_packet(0x6A, payload)

    def check_learned(self):
        payload = bytearray(16)
        payload[0] = 4
        resp = self._send_packet(0x6A, payload)
        err = int.from_bytes(resp[0x22:0x24], "little")
        if err != 0:
            return None
        dec = _aes_cbc("decrypt", self.key, self.iv, resp[0x38:])
        return dec[4:].rstrip(b"\x00")

    def check_sensors(self) -> dict:
        """RM4 Pro exposes temperature + humidity. RM Mini returns an error."""
        payload = bytearray(16)
        payload[0] = 0x24
        resp = self._send_packet(0x6A, payload)
        err = int.from_bytes(resp[0x22:0x24], "little")
        if err != 0:
            raise RuntimeError(f"check_sensors error {err}")
        dec = _aes_cbc("decrypt", self.key, self.iv, resp[0x38:])
        # dec[4:6] = temp*10, dec[6:7] = humidity — device-dependent format
        temperature = dec[4] + dec[5] / 10.0
        humidity = dec[6] + dec[7] / 10.0
        return {"temperature": round(temperature, 1), "humidity": round(humidity, 1)}


# ---- IR codes store (per-device, user-local) ----

def _codes_file(device_key: str) -> Path:
    return IR_CODES_DIR / f"{device_key}.json"


def _load_codes(device_key: str) -> dict:
    path = _codes_file(device_key)
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_codes(device_key: str, codes: dict) -> None:
    IR_CODES_DIR.mkdir(parents=True, exist_ok=True)
    with open(_codes_file(device_key), "w") as f:
        json.dump(codes, f, indent=2, sort_keys=True)


def _decode_ir_blob(code_str: str) -> bytes:
    s = code_str.strip()
    if all(c in "0123456789abcdefABCDEF" for c in s):
        return bytes.fromhex(s)
    return base64.b64decode(s)


# ---- action dispatch ----

def execute(device_config: dict, command_name: str, cmd_spec: dict, params: list) -> dict:
    ip = device_config.get("ip", "")
    if not ip:
        return {"ok": False, "error": "No target IP. Run 'devices' to discover first."}

    conn = device_config.get("connection", {}) or {}
    port = int(conn.get("port", 80))
    device_key = device_config.get("_key") or device_config.get("name") or ip

    action = (cmd_spec.get("action") or "").strip()
    if not action:
        return {"ok": False, "error": f"Command '{command_name}' has no action"}

    # actions:
    #   "send_code:<name>"         — send user-learned IR code by name
    #   "send_code"                — param[0] is the code name
    #   "send_raw"                 — param[0] is hex/base64 IR blob
    #   "learn" / "learn:<name>"   — capture IR and save under ~/.lan-control
    #   "list_codes"               — list learned code names for this device
    #   "check_sensors"            — RM4 Pro temperature/humidity
    session = BroadlinkSession(ip, port=port)
    try:
        session.discover_and_auth()
    except (socket.timeout, RuntimeError) as e:
        return {"ok": False, "error": f"auth failed: {e}"}

    try:
        if action == "list_codes":
            codes = _load_codes(device_key)
            return {"ok": True,
                    "output": json.dumps({"names": sorted(codes.keys())})}

        if action.startswith("send_code"):
            name = action.split(":", 1)[1] if ":" in action else (params[0] if params else "")
            if not name:
                return {"ok": False, "error": "send_code requires a code name"}
            codes = _load_codes(device_key)
            if name not in codes:
                return {"ok": False, "error": f"no learned code '{name}'",
                        "output": json.dumps({"known": sorted(codes.keys())})}
            try:
                session.send_ir(_decode_ir_blob(codes[name]))
            except RuntimeError as e:
                return {"ok": False, "error": str(e)}
            return {"ok": True, "output": json.dumps({"sent": name})}

        if action == "send_raw":
            if not params:
                return {"ok": False, "error": "send_raw requires a hex/base64 blob"}
            try:
                session.send_ir(_decode_ir_blob(params[0]))
            except (ValueError, RuntimeError) as e:
                return {"ok": False, "error": str(e)}
            return {"ok": True, "output": json.dumps({"bytes": len(params[0])})}

        if action.startswith("learn"):
            name = action.split(":", 1)[1] if ":" in action else (params[0] if params else "")
            if not name:
                return {"ok": False, "error": "learn requires a code name"}
            session.enter_learning()
            for i in range(15):
                time.sleep(1)
                data = session.check_learned()
                if data and len(data) > 4:
                    codes = _load_codes(device_key)
                    codes[name] = data.hex()
                    _save_codes(device_key, codes)
                    return {"ok": True, "output": json.dumps(
                        {"learned": name, "bytes": len(data),
                         "stored": str(_codes_file(device_key))}
                    )}
            return {"ok": False, "error": "no IR signal captured in 15s"}

        if action == "check_sensors":
            try:
                data = session.check_sensors()
            except RuntimeError as e:
                return {"ok": False, "error": str(e)}
            return {"ok": True, "output": json.dumps(data)}

        return {"ok": False, "error": f"Unsupported action '{action}'"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
