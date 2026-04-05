"""
UniFi Controller API tools — DG-1.

Provides real-time wireless client inventory and AP health data that syslog
alone cannot give: who is connected right now, to which AP, with what signal,
and per-AP utilisation/satisfaction metrics.

Complements query_wireless_health (which surfaces historical auth failures and
deauth events from syslog) by adding the live client layer needed to identify
devices flagged in those events.

Auth: session cookie via POST /api/login. Credentials stored in .env as
UNIFI_USERNAME / UNIFI_PASSWORD. Controller at UNIFI_HOST:UNIFI_PORT
(default unifi.mcducklabs.com:8443).

Required .env vars:
  UNIFI_USERNAME   controller username (e.g. firstlight)
  UNIFI_PASSWORD   controller password
Optional:
  UNIFI_HOST       default: unifi.mcducklabs.com
  UNIFI_PORT       default: 8443
  UNIFI_SITE       default: default
"""

import json
import logging
from functools import lru_cache
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)

_SESSION_COOKIE: Optional[str] = None
_CSRF_TOKEN: Optional[str] = None


def _base_url() -> str:
    cfg = get_config()
    host = cfg.unifi_host or "unifi.mcducklabs.com"
    port = cfg.unifi_port or 8443
    return f"https://{host}:{port}"


def _login(client: httpx.Client) -> bool:
    """Authenticate and store session cookie. Returns True on success."""
    global _SESSION_COOKIE, _CSRF_TOKEN
    cfg = get_config()
    username = cfg.unifi_username
    password = cfg.unifi_password
    if not username or not password:
        return False
    try:
        resp = client.post(
            f"{_base_url()}/api/login",
            json={"username": username, "password": password},
            timeout=10,
        )
        if resp.status_code == 200 and resp.json().get("meta", {}).get("rc") == "ok":
            _SESSION_COOKIE = resp.cookies.get("unifises") or ""
            _CSRF_TOKEN = resp.cookies.get("csrf_token") or ""
            return True
        return False
    except Exception as e:
        logger.warning("UniFi login failed: %s", e)
        return False


def _get(path: str) -> Optional[dict]:
    """GET a UniFi API path, re-authenticating once if needed."""
    global _SESSION_COOKIE, _CSRF_TOKEN
    cfg = get_config()
    site = cfg.unifi_site or "default"
    url = f"{_base_url()}/api/s/{site}/{path}"

    with httpx.Client(verify=False, timeout=15) as client:  # noqa: S501 — self-signed cert
        # Try with existing session first
        for attempt in range(2):
            if not _SESSION_COOKIE:
                if not _login(client):
                    return {"error": "UniFi login failed — check UNIFI_USERNAME/UNIFI_PASSWORD in .env"}

            headers = {}
            if _CSRF_TOKEN:
                headers["X-Csrf-Token"] = _CSRF_TOKEN

            resp = client.get(
                url,
                cookies={"unifises": _SESSION_COOKIE},
                headers=headers,
                timeout=15,
            )

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code in (401, 403) and attempt == 0:
                # Session expired — force re-login
                _SESSION_COOKIE = None
                _CSRF_TOKEN = None
                _login(client)
                continue

            return {"error": f"HTTP {resp.status_code}"}

    return {"error": "request failed"}


@tool
def query_unifi_clients() -> str:
    """Get all currently connected Wi-Fi clients from the UniFi controller.

    Returns each wireless client's MAC, hostname, IP, AP name, SSID, signal
    strength (dBm), satisfaction score, channel, and uptime. Use this to:
    - Identify a device by MAC when auth failure logs surface an unknown MAC
    - Find clients with poor signal (signal < -75 dBm) or low satisfaction
    - Count clients per AP to detect overloaded access points
    - Spot unexpected clients (unknown hostnames, guest network devices)

    Returns:
        JSON with total client count and per-client detail, sorted by AP then signal.
    """
    cfg = get_config()
    if not cfg.unifi_username or not cfg.unifi_password:
        return json.dumps({"error": "UNIFI_USERNAME / UNIFI_PASSWORD not configured in .env"})

    data = _get("stat/sta")
    if isinstance(data, dict) and "error" in data:
        return json.dumps(data)

    clients = data.get("data", [])
    wireless = [c for c in clients if not c.get("is_wired")]

    result = []
    for c in wireless:
        result.append({
            "mac": c.get("mac"),
            "hostname": c.get("hostname") or c.get("oui") or "unknown",
            "ip": c.get("ip") or c.get("last_ip"),
            "ap": c.get("last_uplink_name"),
            "ssid": c.get("essid"),
            "signal_dbm": c.get("signal"),
            "rssi": c.get("rssi"),
            "satisfaction": c.get("satisfaction"),
            "channel": c.get("channel"),
            "radio": c.get("radio"),
            "tx_rate_mbps": round(c.get("tx_rate", 0) / 1000, 1) if c.get("tx_rate") else None,
            "rx_rate_mbps": round(c.get("rx_rate", 0) / 1000, 1) if c.get("rx_rate") else None,
            "uptime_s": c.get("uptime"),
            "tx_retries_pct": c.get("wifi_tx_retries_percentage"),
        })

    # Sort by AP name, then signal strength descending
    result.sort(key=lambda x: (x.get("ap") or "", -(x.get("signal_dbm") or -999)))

    poor_signal = [c for c in result if (c.get("signal_dbm") or 0) < -75]
    low_satisfaction = [c for c in result if (c.get("satisfaction") or 100) < 50]

    return json.dumps({
        "total_wireless_clients": len(result),
        "poor_signal_count": len(poor_signal),
        "low_satisfaction_count": len(low_satisfaction),
        "clients": result,
    }, indent=2)


@tool
def query_unifi_ap_stats() -> str:
    """Get per-access-point health and utilisation metrics from the UniFi controller.

    Returns for each AP: client count, channel, channel utilisation, satisfaction,
    TX/RX bytes, uptime, and radio table stats (2.4 GHz and 5 GHz separately).
    Use this to:
    - Find overloaded APs (high client count or channel utilisation)
    - Identify APs with poor overall satisfaction scores
    - Confirm which AP a roaming client is failing on
    - Check AP uptime (unexpected restarts indicate hardware/power issues)

    Returns:
        JSON with per-AP summary sorted by client count descending.
    """
    cfg = get_config()
    if not cfg.unifi_username or not cfg.unifi_password:
        return json.dumps({"error": "UNIFI_USERNAME / UNIFI_PASSWORD not configured in .env"})

    data = _get("stat/device")
    if isinstance(data, dict) and "error" in data:
        return json.dumps(data)

    devices = data.get("data", [])
    aps = [d for d in devices if d.get("type") == "uap" or d.get("model", "").startswith("U")]

    result = []
    for ap in aps:
        radios = []
        for r in ap.get("radio_table_stats", []):
            radios.append({
                "band": "2.4GHz" if r.get("radio") == "ng" else "5GHz",
                "channel": r.get("channel"),
                "utilisation_pct": r.get("cu_total"),
                "clients": r.get("num_sta"),
                "tx_retries": r.get("tx_retries"),
            })

        result.append({
            "name": ap.get("name") or ap.get("hostname"),
            "model": ap.get("model"),
            "ip": ap.get("ip"),
            "clients": ap.get("num_sta", 0),
            "satisfaction": ap.get("satisfaction"),
            "uptime_s": ap.get("uptime"),
            "tx_bytes": ap.get("tx_bytes"),
            "rx_bytes": ap.get("rx_bytes"),
            "radios": radios,
            "version": ap.get("version"),
        })

    result.sort(key=lambda x: x.get("clients", 0), reverse=True)

    return json.dumps({
        "ap_count": len(result),
        "total_clients": sum(ap.get("clients", 0) for ap in result),
        "access_points": result,
    }, indent=2)


@tool
def lookup_unifi_client_by_mac(mac: str) -> str:
    """Look up a specific Wi-Fi client by MAC address in the UniFi controller.

    Use this when a MAC address appears in auth failure logs, deauth events,
    or ntopng alerts — to identify what device it is, whether it's currently
    connected, and its signal/satisfaction details.

    Args:
        mac: MAC address to look up (e.g. "d8:d5:b9:00:bb:9f")

    Returns:
        JSON with device details if found, or not_found if the MAC is unknown
        to the controller (could be a device that was never successfully connected).
    """
    cfg = get_config()
    if not cfg.unifi_username or not cfg.unifi_password:
        return json.dumps({"error": "UNIFI_USERNAME / UNIFI_PASSWORD not configured in .env"})

    # Check currently connected clients first
    data = _get("stat/sta")
    if isinstance(data, dict) and "error" in data:
        return json.dumps(data)

    mac_lower = mac.lower().strip()
    for c in data.get("data", []):
        if (c.get("mac") or "").lower() == mac_lower:
            return json.dumps({
                "found": True,
                "currently_connected": True,
                "mac": c.get("mac"),
                "hostname": c.get("hostname") or c.get("oui") or "unknown",
                "ip": c.get("ip") or c.get("last_ip"),
                "ap": c.get("last_uplink_name"),
                "ssid": c.get("essid"),
                "signal_dbm": c.get("signal"),
                "satisfaction": c.get("satisfaction"),
                "uptime_s": c.get("uptime"),
                "first_seen": c.get("first_seen"),
                "last_seen": c.get("last_seen"),
                "oui": c.get("oui"),
            }, indent=2)

    # Check all known devices (including recently disconnected)
    history = _get("stat/alluser")
    if not isinstance(history, dict) or "error" not in history:
        for c in history.get("data", []):
            if (c.get("mac") or "").lower() == mac_lower:
                return json.dumps({
                    "found": True,
                    "currently_connected": False,
                    "mac": c.get("mac"),
                    "hostname": c.get("hostname") or c.get("oui") or "unknown",
                    "ip": c.get("last_ip"),
                    "ap": c.get("last_uplink_name"),
                    "first_seen": c.get("first_seen"),
                    "last_seen": c.get("last_seen"),
                    "oui": c.get("oui"),
                }, indent=2)

    return json.dumps({"found": False, "mac": mac, "note": "MAC not known to UniFi controller"})
