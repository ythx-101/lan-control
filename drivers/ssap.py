"""
SSAP protocol driver — controls LG webOS TVs via WebSocket.

Uses SSAP (Smart Service Access Protocol) over TLS WebSocket (port 3001).
Supports pairing with client key persistence and Wake-on-LAN.

Driver interface:
    execute(device_config, command_name, cmd_spec, params) -> dict
"""
import asyncio
import json
import os
import ssl
import time
from pathlib import Path

try:
    import websockets
except ImportError:
    websockets = None

try:
    from wakeonlan import send_magic_packet
except ImportError:
    send_magic_packet = None

# Client key storage (shared with lan-control state)
KEYS_FILE = Path.home() / ".lan-control" / "ssap_keys.json"

# Registration payload (from aiopylgtv / LG Connect SDK)
_SIGNATURE = (
    "eyJhbGdvcml0aG0iOiJSU0EtU0hBMjU2Iiwia2V5SWQiOiJ0ZXN0LXNpZ25pbm"
    "ctY2VydCIsInNpZ25hdHVyZVZlcnNpb24iOjF9.hrVRgjCwXVvE2OOSpDZ58hR"
    "+59aFNwYDyjQgKk3auukd7pcegmE2CzPCa0bJ0ZsRAcKkCTJrWo5iDzNhMBWRy"
    "aMOv5zWSrthlf7G128qvIlpMT0YNY+n/FaOHE73uLrS/g7swl3/qH/BGFG2Hu4"
    "RlL48eb3lLKqTt2xKHdCs6Cd4RMfJPYnzgvI4BNrFUKsjkcu+WD4OO2A27Pq1n"
    "50cMchmcaXadJhGrOqH5YmHdOCj5NSHzJYrsW0HPlpuAx/ECMeIZYDh6RMqaFM"
    "2DXzdKX9NmmyqzJ3o/0lkk/N97gfVRLW5hA29yeAwaCViZNCP8iC9aO0q9fQoj"
    "oa7NQnAtw=="
)

_REGISTRATION_PAYLOAD = {
    "forcePairing": False,
    "manifest": {
        "appVersion": "1.1",
        "manifestVersion": 1,
        "permissions": [
            "LAUNCH", "LAUNCH_WEBAPP", "APP_TO_APP", "CLOSE",
            "CONTROL_AUDIO", "CONTROL_DISPLAY", "CONTROL_INPUT_JOYSTICK",
            "CONTROL_INPUT_MEDIA_PLAYBACK", "CONTROL_INPUT_TV",
            "CONTROL_POWER", "CONTROL_TV_SCREEN",
            "READ_APP_STATUS", "READ_CURRENT_CHANNEL", "READ_INPUT_DEVICE_LIST",
            "READ_NETWORK_STATE", "READ_RUNNING_APPS", "READ_TV_CHANNEL_LIST",
            "WRITE_NOTIFICATION_TOAST", "READ_POWER_STATE", "READ_COUNTRY_INFO",
            "CONTROL_INPUT_TEXT", "CONTROL_MOUSE_AND_KEYBOARD",
            "READ_INSTALLED_APPS", "READ_SETTINGS",
        ],
        "signatures": [{"signature": _SIGNATURE, "signatureVersion": 1}],
        "signed": {
            "appId": "com.lge.test",
            "created": "20140509",
            "localizedAppNames": {"": "LG Remote App"},
            "localizedVendorNames": {"": "LG Electronics"},
            "serial": "2f930e2d2cfe083771f68e4fe7bb07",
            "vendorId": "com.lge",
        },
    },
    "pairingType": "PROMPT",
}

WS_TIMEOUT = 10


# ── Key management ──────────────────────────────────────────────

def _load_keys() -> dict:
    if KEYS_FILE.exists():
        try:
            with open(KEYS_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_keys(keys: dict):
    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)


def _get_client_key(ip: str) -> str | None:
    return _load_keys().get(ip)


def _set_client_key(ip: str, key: str):
    keys = _load_keys()
    keys[ip] = key
    _save_keys(keys)


# ── WebSocket helpers ───────────────────────────────────────────

def _get_ssl_context() -> ssl.SSLContext:
    """SSL context that accepts LG TVs' self-signed certificates."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _ssap_connect(ip: str, port: int = 3001, client_key: str | None = None,
                        pairing_timeout: float = 30) -> "websockets.WebSocketClientProtocol":
    """
    Connect to LG webOS TV via SSAP WebSocket.

    Handles first-time pairing (shows prompt on TV) and subsequent
    connections using saved client key.
    """
    if websockets is None:
        raise RuntimeError("websockets not installed. Run: pip install websockets")

    ssl_ctx = _get_ssl_context()
    url = f"wss://{ip}:{port}"

    ws = await asyncio.wait_for(
        websockets.connect(
            url, ssl=ssl_ctx,
            ping_interval=None,
            close_timeout=WS_TIMEOUT,
            max_size=None,
            open_timeout=WS_TIMEOUT,
        ),
        timeout=WS_TIMEOUT,
    )

    import copy
    reg_msg = {
        "type": "register",
        "id": "register_0",
        "payload": copy.deepcopy(_REGISTRATION_PAYLOAD),
    }
    if client_key:
        reg_msg["payload"]["client-key"] = client_key

    await ws.send(json.dumps(reg_msg))

    raw = await asyncio.wait_for(ws.recv(), timeout=WS_TIMEOUT)
    resp = json.loads(raw)
    resp_type = resp.get("type", "")
    payload = resp.get("payload", {})

    # First-time pairing: wait for user to accept on TV
    if resp_type == "response" and payload.get("pairingType") == "PROMPT":
        try:
            raw2 = await asyncio.wait_for(ws.recv(), timeout=pairing_timeout)
            resp2 = json.loads(raw2)
            if resp2.get("type") == "registered":
                new_key = resp2["payload"].get("client-key")
                if new_key:
                    _set_client_key(ip, new_key)
                    return ws
        except asyncio.TimeoutError:
            await ws.close()
            raise TimeoutError(
                f"Pairing timeout. Accept the prompt on TV ({ip}) within {pairing_timeout}s."
            )
        await ws.close()
        raise ConnectionError("Pairing was not accepted on the TV.")

    # Registration failed
    if resp_type == "response" and payload.get("returnValue") is False:
        error = payload.get("errorText", payload.get("errorCode", "Unknown error"))
        await ws.close()
        raise ConnectionError(f"SSAP registration failed: {error}")

    return ws


async def _ssap_request(ip: str, uri: str, payload: dict | None = None,
                        port: int = 3001) -> dict:
    """Send SSAP request and return response payload."""
    client_key = _get_client_key(ip)
    ws = await _ssap_connect(ip, port, client_key)

    try:
        cmd = {
            "type": "request",
            "id": 1,
            "uri": uri,
            "payload": payload or {},
        }
        await ws.send(json.dumps(cmd))

        # Read until we get a matching response (skip notifications)
        deadline = time.monotonic() + WS_TIMEOUT
        while time.monotonic() < deadline:
            try:
                remaining = deadline - time.monotonic()
                raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, remaining))
                data = json.loads(raw)
                if data.get("type") == "response" and data.get("id") == 1:
                    return data.get("payload", {})
            except asyncio.TimeoutError:
                break

        return {"returnValue": False, "errorText": "Timeout waiting for response"}
    finally:
        await ws.close()


async def _ssap_send_only(ip: str, uri: str, payload: dict | None = None,
                          port: int = 3001) -> dict:
    """Fire-and-forget SSAP command (volume_up/down, play/pause)."""
    client_key = _get_client_key(ip)
    ws = await _ssap_connect(ip, port, client_key)
    try:
        cmd = {
            "type": "request",
            "id": 1,
            "uri": uri,
            "payload": payload or {},
        }
        await ws.send(json.dumps(cmd))
        await asyncio.sleep(0.2)
        return {"returnValue": True}
    finally:
        await ws.close()


async def _send_wol(mac: str):
    """Send Wake-on-LAN magic packet."""
    if send_magic_packet is None:
        raise RuntimeError("wakeonlan not installed. Run: pip install wakeonlan")
    send_magic_packet(mac)


async def _screenshot(ip: str, port: int = 3001) -> str:
    """Capture TV screen screenshot (returns base64 image data)."""
    payload = await _ssap_request(ip, "ssap://tv/getScreenImage", port=port)
    if "imageData" in payload:
        return payload["imageData"]
    raise RuntimeError(
        "Screenshot not supported. The TV may not expose getScreenImage."
    )


# ── Public interface ────────────────────────────────────────────

# Commands that don't need a response (quick execution)
_FIRE_AND_FORGET = {"volume_up", "volume_down", "play", "pause"}


def execute(device_config: dict, command_name: str, cmd_spec: dict, params: list) -> dict:
    """
    Execute an SSAP command on an LG webOS TV.

    Called by drivers/__init__.py with the standard driver interface.
    """
    ip = device_config.get("ip", "")
    if not ip:
        return {"ok": False, "error": "No target IP. Run 'devices' to discover devices first."}

    conn = device_config.get("connection", {})
    port = conn.get("port", 3001)

    action = cmd_spec.get("action", "")
    if not action:
        return {"ok": False, "error": f"Command '{command_name}' has no action defined"}

    # Wake-on-LAN
    if action == "WOL":
        mac = device_config.get("mac", "")
        if not mac:
            return {"ok": False, "error": "No MAC address for WOL. Set 'mac' in device config."}
        try:
            asyncio.run(_send_wol(mac))
            return {"ok": True, "output": f"WOL packet sent to {mac}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # Screenshot
    if action == "custom://screenshot":
        try:
            img_data = asyncio.run(_screenshot(ip, port))
            return {"ok": True, "output": img_data, "format": "base64_image"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # SSAP URI commands
    if not action.startswith("ssap://"):
        return {"ok": False, "error": f"Unsupported action: {action}"}

    # Build payload from params
    payload = {}
    param_names = cmd_spec.get("params", [])
    if params and param_names:
        for i, name in enumerate(param_names):
            if i < len(params):
                val = params[i]
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    pass
                payload[name] = val
    elif params:
        for i, p in enumerate(params):
            try:
                p = int(p)
            except (ValueError, TypeError):
                pass
            payload[f"param{i}"] = p

    try:
        if command_name in _FIRE_AND_FORGET:
            result = asyncio.run(_ssap_send_only(ip, action, payload, port))
        else:
            result = asyncio.run(_ssap_request(ip, action, payload, port))

        if result.get("returnValue", False) is not False:
            # Format app list nicely
            if "apps" in result or "launchPoints" in result:
                apps = result.get("apps") or result.get("launchPoints", [])
                lines = [
                    f"  {a.get('title', a.get('id', '?'))}: {a.get('id', '?')}"
                    for a in apps[:30]
                ]
                return {"ok": True, "output": "\n".join(lines), "data": result}
            return {
                "ok": True,
                "output": json.dumps(result, indent=2)[:4096],
                "data": result,
            }
        else:
            error = result.get("errorText", result.get("errorCode", "Command failed"))
            return {"ok": False, "error": f"SSAP error: {error}", "data": result}

    except ConnectionError as e:
        return {"ok": False, "error": str(e)}
    except TimeoutError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"SSAP command failed: {e}"}
