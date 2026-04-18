"""
SSAP protocol driver — LG webOS TV control over secure WebSocket (wss).

No external deps. Uses stdlib ssl/socket for WebSocket framing.

Secrets (pairing client-key per device) are stored in
~/.lan-control/secrets.yaml and never committed. First use prompts for
on-screen pairing.
"""
import base64
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import uuid
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

STATE_DIR = Path.home() / ".lan-control"
SECRETS_FILE = STATE_DIR / "secrets.yaml"

# LG SDK test-signing manifest signature. Public constant shared by all
# webOS client libraries (e.g. python-webostv). Safe to embed.
_TEST_SIG = (
    "eyJhbGdvcml0aG0iOiJSU0EtU0hBMjU2Iiwia2V5SWQiOiJ0ZXN0LXNpZ25pbmctY2VydCIs"
    "InNpZ25hdHVyZVZlcnNpb24iOjF9.hrVRgjCwXVvE2OOSpDZ58hR+59aFNwYDyjQgKk3auu"
    "kd7pcegmE2CzPCa0bJ0ZsRAcKkCTJrWo5iDzNhMBWRyaMOv5zWSrthlf7G128qvIlpMT0YN"
    "Y+n/FaOHE73uLrS/g7swl3/qH/BGFG2Hu4RlL48eb3lLKqTt2xKHdCs6Cd4RMfJPYnzgvI4"
    "BNrFUKsjkcu+WD4OO2A27Pq1n50cMchmcaXadJhGrOqH5YmHdOCj5NSHzJYrsW0HPlpuAx/"
    "ECMeIZYDh6RMqaFM2DXzdKX9NmmyqzJ3o/0lkk/N97gfVRLW5hA29yeAwaCViZNCP8iC9aO"
    "0q9fQojoa7NQnAtw=="
)

_ALL_PERMS = [
    "LAUNCH", "LAUNCH_WEBAPP", "APP_TO_APP", "CLOSE", "TEST_OPEN",
    "TEST_PROTECTED", "CONTROL_AUDIO", "CONTROL_DISPLAY",
    "CONTROL_INPUT_JOYSTICK", "CONTROL_INPUT_MEDIA_RECORDING",
    "CONTROL_INPUT_MEDIA_PLAYBACK", "CONTROL_INPUT_TV", "CONTROL_POWER",
    "READ_APP_STATUS", "READ_CURRENT_CHANNEL", "READ_INPUT_DEVICE_LIST",
    "READ_NETWORK_STATE", "READ_RUNNING_APPS", "READ_TV_CHANNEL_LIST",
    "WRITE_NOTIFICATION", "READ_POWER_STATE", "READ_COUNTRY_INFO",
    "READ_SETTINGS", "CONTROL_TV_SCREEN", "CONTROL_TV_STANBY",
    "CONTROL_FAVORITE_GROUP", "CONTROL_USER_INFO", "CHECK_BLUETOOTH_DEVICE",
    "CONTROL_BLUETOOTH", "CONTROL_TIMER_INFO", "STB_INTERNAL_CONNECTION",
    "CONTROL_RECORDING", "READ_RECORDING_STATE", "WRITE_RECORDING_LIST",
    "READ_RECORDING_LIST", "READ_RECORDING_SCHEDULE",
    "WRITE_RECORDING_SCHEDULE", "READ_STORAGE_DEVICE_LIST",
    "READ_TV_PROGRAM_INFO", "CONTROL_BOX_CHANNEL", "READ_TV_ACR_AUTH_TOKEN",
    "READ_TV_CONTENT_STATE", "READ_TV_CURRENT_TIME", "ADD_LAUNCHER_CHANNEL",
    "SET_CHANNEL_SKIP", "RELEASE_CHANNEL_SKIP", "CONTROL_CHANNEL_BLOCK",
    "DELETE_SELECT_CHANNEL", "CONTROL_CHANNEL_GROUP", "SCAN_TV_CHANNELS",
    "CONTROL_TV_POWER", "CONTROL_WOL",
]

_SIGNED_PERMS = [
    "TEST_SECURE", "CONTROL_INPUT_TEXT", "CONTROL_MOUSE_AND_KEYBOARD",
    "READ_INSTALLED_APPS", "READ_LGE_SDX", "READ_NOTIFICATIONS", "SEARCH",
    "WRITE_SETTINGS", "WRITE_NOTIFICATION_ALERT", "CONTROL_POWER",
    "READ_CURRENT_CHANNEL", "READ_RUNNING_APPS", "READ_UPDATE_INFO",
    "UPDATE_FROM_REMOTE_APP", "READ_LGE_TV_INPUT_EVENTS",
    "READ_TV_CURRENT_TIME",
]

VALID_BUTTONS = {
    "LEFT", "RIGHT", "DOWN", "UP", "HOME", "BACK", "ENTER", "DASH", "INFO",
    "MUTE", "RED", "GREEN", "BLUE", "YELLOW", "VOLUMEUP", "VOLUMEDOWN",
    "CHANNELUP", "CHANNELDOWN", "PLAY", "PAUSE", "STOP", "REWIND",
    "FASTFORWARD", "EXIT", "CC", "ASTERISK",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
}


# ---- secrets store ----

def _load_secrets() -> dict:
    if not SECRETS_FILE.exists() or yaml is None:
        return {}
    try:
        with open(SECRETS_FILE) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _save_secrets(data: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if yaml is None:
        # Fallback to JSON if pyyaml unavailable
        with open(SECRETS_FILE, "w") as f:
            json.dump(data, f, indent=2)
    else:
        with open(SECRETS_FILE, "w") as f:
            yaml.safe_dump(data, f)
    try:
        os.chmod(SECRETS_FILE, 0o600)
    except OSError:
        pass


def _get_client_key(device_id: str) -> str:
    secrets = _load_secrets()
    return secrets.get("ssap", {}).get(device_id, "")


def _set_client_key(device_id: str, key: str) -> None:
    secrets = _load_secrets()
    secrets.setdefault("ssap", {})[device_id] = key
    _save_secrets(secrets)


# ---- WebSocket minimal impl ----

def _ws_send(sock, data):
    payload = data.encode() if isinstance(data, str) else data
    mask = os.urandom(4)
    frame = bytearray([0x81])
    l = len(payload)
    if l < 126:
        frame.append(0x80 | l)
    elif l < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack(">H", l))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack(">Q", l))
    frame.extend(mask)
    for i, b in enumerate(payload):
        frame.append(b ^ mask[i % 4])
    sock.send(bytes(frame))


def _ws_recv(sock, timeout=8):
    sock.settimeout(timeout)
    try:
        h = sock.recv(2)
        if not h or len(h) < 2:
            return None
        length = h[1] & 0x7f
        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(65536, length - len(data)))
            if not chunk:
                break
            data += chunk
        return data.decode(errors="replace")
    except socket.timeout:
        return None


def _ws_connect(host, port, path="/"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, port), timeout=10)
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    ssock.send(req.encode())
    resp = ssock.recv(4096).decode()
    if "101" not in resp:
        raise RuntimeError(f"WebSocket handshake failed: {resp[:120]}")
    return ssock


# ---- SSAP session ----

class SSAPSession:
    def __init__(self, host, port, device_id, app_name="lan-control"):
        self.host = host
        self.port = port
        self.device_id = device_id
        self.app_name = app_name
        self.sock = None

    def connect(self):
        self.sock = _ws_connect(self.host, self.port)
        return self.sock

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _build_manifest(self, client_key):
        # Serial is random per install — no user-identifying info
        serial = uuid.uuid4().hex[:28]
        manifest = {
            "manifestVersion": 1,
            "appVersion": "1.1",
            "signed": {
                "created": "20140509",
                "appId": "com.lge.test",
                "vendorId": "com.lge",
                "localizedAppNames": {"": self.app_name},
                "localizedVendorNames": {"": "LG Electronics"},
                "permissions": _SIGNED_PERMS,
                "serial": serial,
            },
            "permissions": _ALL_PERMS,
            "signatures": [
                {"signatureVersion": 1, "signature": _TEST_SIG},
            ],
        }
        payload = {"pairingType": "PROMPT", "manifest": manifest}
        if client_key:
            payload["client-key"] = client_key
        return payload

    def register(self):
        """Register. If no saved key, prompt pairing on TV, then save key."""
        client_key = _get_client_key(self.device_id)
        reg = json.dumps({
            "type": "register",
            "id": "reg",
            "payload": self._build_manifest(client_key),
        })
        _ws_send(self.sock, reg)

        # Collect responses. Pairing flow may emit "response" first, then
        # "registered" once user accepts the prompt on TV.
        deadline = time.time() + 30
        new_key = None
        while time.time() < deadline:
            data = _ws_recv(self.sock, 3)
            if not data:
                continue
            try:
                msg = json.loads(data)
            except ValueError:
                continue
            if msg.get("type") == "registered":
                new_key = msg.get("payload", {}).get("client-key")
                if new_key and new_key != client_key:
                    _set_client_key(self.device_id, new_key)
                return True
            if msg.get("type") == "error":
                raise RuntimeError(msg.get("error", "pairing error"))
        return False

    def request(self, uri, payload=None, cmd_id=None):
        cmd_id = cmd_id or uuid.uuid4().hex[:8]
        msg = {"type": "request", "id": cmd_id, "uri": uri}
        if payload is not None:
            msg["payload"] = payload
        _ws_send(self.sock, json.dumps(msg))
        data = _ws_recv(self.sock)
        if not data:
            return None
        try:
            return json.loads(data)
        except ValueError:
            return {"raw": data}

    def get_pointer_socket_path(self):
        resp = self.request(
            "ssap://com.webos.service.networkinput/getPointerInputSocket",
            cmd_id="pointer",
        )
        if not resp:
            return None
        return resp.get("payload", {}).get("socketPath")


def _send_buttons(session, buttons, delay=0.5):
    path = session.get_pointer_socket_path()
    if not path:
        return {"ok": False, "error": "no pointer socket"}
    m = re.match(r"wss?://([^:]+):(\d+)(/.+)", path)
    if not m:
        return {"ok": False, "error": f"bad socket path: {path}"}
    host, port, ws_path = m.group(1), int(m.group(2)), m.group(3)
    psock = _ws_connect(host, port, ws_path)
    try:
        sent = []
        for btn in buttons:
            _ws_send(psock, f"type:button\nname:{btn}\n\n")
            sent.append(btn)
            time.sleep(delay)
        return {"ok": True, "output": json.dumps({"buttons": sent})}
    finally:
        try:
            psock.close()
        except Exception:
            pass


def _download_image(uri, save_path):
    m = re.match(r"https?://([^:/]+):?(\d+)?(/.+)", uri)
    if not m:
        return {"ok": False, "error": f"cannot parse image URI: {uri}"}
    host, port, rpath = m.group(1), int(m.group(2) or 443), m.group(3)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.create_connection((host, port), timeout=15)
    s = ctx.wrap_socket(s, server_hostname=host)
    try:
        s.send(f"GET {rpath} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    finally:
        s.close()
    body = resp.split(b"\r\n\r\n", 1)[-1]
    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "wb") as f:
        f.write(body)
    return {"ok": True, "output": json.dumps({"path": save_path, "size": len(body)})}


# ---- action dispatch ----

def _substitute(text, params, cmd_spec):
    """Replace {0},{1},{name} placeholders in text."""
    if not text or not params:
        return text
    out = text
    for i, p in enumerate(params):
        out = out.replace(f"{{{i}}}", str(p))
    for name, value in zip(cmd_spec.get("params", []) or [], params):
        out = out.replace(f"{{{name}}}", str(value))
    return out


def _parse_payload(cmd_spec, params):
    """Build SSAP payload from cmd_spec.payload (may contain placeholders)."""
    raw = cmd_spec.get("payload")
    if raw is None:
        return None
    if isinstance(raw, str):
        filled = _substitute(raw, params, cmd_spec)
        try:
            return json.loads(filled)
        except ValueError:
            return {"value": filled}
    if isinstance(raw, dict):
        filled = {}
        for k, v in raw.items():
            if isinstance(v, str):
                sv = _substitute(v, params, cmd_spec)
                # Auto-cast numeric literals for fields like "volume"
                if sv.lstrip("-").isdigit():
                    filled[k] = int(sv)
                else:
                    filled[k] = sv
            else:
                filled[k] = v
        return filled
    return raw


def execute(device_config: dict, command_name: str, cmd_spec: dict, params: list) -> dict:
    ip = device_config.get("ip", "")
    if not ip:
        return {"ok": False, "error": "No target IP. Run 'devices' to discover first."}

    conn = device_config.get("connection", {}) or {}
    port = int(conn.get("port", 3001))
    device_id = device_config.get("_key") or device_config.get("name") or ip
    app_name = conn.get("app_name", "lan-control")

    action = (cmd_spec.get("action") or "").strip()
    if not action:
        return {"ok": False, "error": f"Command '{command_name}' has no action"}

    # WOL is out of scope of SSAP driver
    if action.upper() == "WOL":
        return {"ok": False, "error": "WOL requires MAC and is not implemented in ssap driver"}

    session = SSAPSession(ip, port, device_id=device_id, app_name=app_name)
    try:
        session.connect()
        if not session.register():
            return {
                "ok": False,
                "error": (
                    "Registration failed. If this is first pair, accept the "
                    "prompt on the TV screen and retry."
                ),
            }

        # button:<NAME>
        if action.startswith("button:"):
            btn = action.split(":", 1)[1].strip().upper()
            if btn == "{0}" and params:
                btn = params[0].upper()
            if btn not in VALID_BUTTONS:
                return {"ok": False, "error": f"unknown button '{btn}'",
                        "output": json.dumps({"valid": sorted(VALID_BUTTONS)})}
            return _send_buttons(session, [btn], delay=0.2)

        # buttons:A,B,C  (or from params[0] as comma list)
        if action.startswith("buttons:"):
            raw = action.split(":", 1)[1]
            if raw.strip() == "{0}" and params:
                raw = params[0]
            delay = 0.5
            parts = [p.strip().upper() for p in raw.split(",") if p.strip()]
            if parts and parts[-1].replace(".", "", 1).isdigit():
                delay = float(parts.pop())
            bad = [p for p in parts if p not in VALID_BUTTONS]
            if bad:
                return {"ok": False, "error": f"unknown buttons: {bad}"}
            return _send_buttons(session, parts, delay=delay)

        # custom://screenshot [save_path]
        if action == "custom://screenshot" or action == "screenshot":
            resp = session.request("ssap://tv/executeOneShot", cmd_id="screenshot")
            if not resp:
                return {"ok": False, "error": "no response from TV"}
            uri = resp.get("payload", {}).get("imageUri", "")
            if not uri:
                return {"ok": False, "error": "no imageUri in response",
                        "output": json.dumps(resp)}
            save_path = params[0] if params else "/tmp/lan-control-screenshot.jpg"
            return _download_image(uri, save_path)

        # custom://alert <message>
        if action == "custom://alert" or action == "alert":
            msg_text = params[0] if params else cmd_spec.get("message", "")
            if not msg_text:
                return {"ok": False, "error": "alert requires a message"}
            buttons = cmd_spec.get("buttons", ["OK"])
            payload = {"message": msg_text,
                       "buttons": [{"label": b} for b in buttons]}
            resp = session.request(
                "ssap://system.notifications/createAlert", payload, cmd_id="alert"
            )
            return {"ok": True, "output": json.dumps(resp)}

        # custom://close_alert <alert_id>
        if action == "custom://close_alert" or action == "close_alert":
            alert_id = params[0] if params else ""
            if not alert_id:
                return {"ok": False, "error": "close_alert requires alert_id"}
            resp = session.request(
                "ssap://system.notifications/closeAlert",
                {"alertId": alert_id},
                cmd_id="close_alert",
            )
            return {"ok": True, "output": json.dumps(resp)}

        # custom://yt_play <video_id>
        if action == "custom://yt_play" or action == "yt_play":
            vid = params[0] if params else ""
            if not vid:
                return {"ok": False, "error": "yt_play requires YouTube video id"}
            resp = session.request(
                "ssap://com.webos.applicationManager/launch",
                {"id": "youtube.leanback.v4",
                 "params": {"contentTarget": f"https://www.youtube.com/watch?v={vid}"}},
                cmd_id="yt_play",
            )
            return {"ok": True, "output": json.dumps(resp)}

        # custom://yt_search <query>  (launch app + drive IME)
        if action == "custom://yt_search" or action == "yt_search":
            query = " ".join(params) if params else ""
            if not query:
                return {"ok": False, "error": "yt_search requires a query"}
            session.request(
                "ssap://com.webos.applicationManager/launch",
                {"id": "youtube.leanback.v4"},
                cmd_id="launch_yt",
            )
            time.sleep(3)
            _send_buttons(session, ["UP", "UP", "UP", "ENTER"], delay=0.8)
            time.sleep(2)
            session.request(
                "ssap://com.webos.service.ime/insertText",
                {"text": query, "replace": 0},
                cmd_id="ime_text",
            )
            time.sleep(1)
            resp = session.request(
                "ssap://com.webos.service.ime/sendEnterKey",
                cmd_id="ime_enter",
            )
            return {"ok": True, "output": json.dumps(resp)}

        # Normal ssap:// URI request
        if action.startswith("ssap://"):
            payload = _parse_payload(cmd_spec, params)
            resp = session.request(action, payload, cmd_id=command_name)
            if resp is None:
                return {"ok": False, "error": "no response from TV"}
            if isinstance(resp, dict) and resp.get("type") == "error":
                return {"ok": False, "error": resp.get("error", "ssap error"),
                        "output": json.dumps(resp)}
            return {"ok": True, "output": json.dumps(resp)}

        return {"ok": False, "error": f"Unsupported action '{action}'"}
    finally:
        session.close()
