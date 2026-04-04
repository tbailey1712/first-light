"""
UniFi Controller tools — client inventory and AP statistics.

Queries the UniFi Network Controller REST API to retrieve connected client
details, AP performance stats, and WLAN configuration.

.env vars required:
  UNIFI_HOST      IP or hostname of UniFi Controller (e.g. unifi.mcducklabs.com)
  UNIFI_PORT      Port (default: 8443)
  UNIFI_USERNAME  Controller admin username
  UNIFI_PASSWORD  Controller admin password
  UNIFI_SITE      Site name (default: default)

Auth: UniFi uses session cookie auth (POST /api/login).
SSL: Controller typically uses a self-signed cert — verification is disabled.

NOTE: These tools do not yet have credentials configured in .env.
      Set UNIFI_HOST, UNIFI_USERNAME, UNIFI_PASSWORD to enable.
"""

import json
import logging
from contextlib import contextmanager
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)


@contextmanager
def _unifi_client():
    """Yield an authenticated httpx.Client for the UniFi Controller API."""
    cfg = get_config()
    host = getattr(cfg, "unifi_host", None)
    if not host:
        raise RuntimeError("UNIFI_HOST not configured in .env")

    port = getattr(cfg, "unifi_port", 8443) or 8443
    username = getattr(cfg, "unifi_username", None)
    password = getattr(cfg, "unifi_password", None)

    if not username or not password:
        raise RuntimeError("UNIFI_USERNAME or UNIFI_PASSWORD not configured in .env")

    base_url = f"https://{host}:{port}"

    with httpx.Client(
        base_url=base_url,
        verify=False,  # Controller ships a self-signed cert
        timeout=20.0,
        follow_redirects=True,
    ) as client:
        # Authenticate — UniFi returns a session cookie
        resp = client.post("/api/login", json={
            "username": username,
            "password": password,
        })
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"UniFi login failed: HTTP {resp.status_code} — "
                "check UNIFI_USERNAME/PASSWORD and controller URL"
            )
        data = resp.json()
        if data.get("meta", {}).get("rc") != "ok":
            raise RuntimeError(f"UniFi login rejected: {data.get('meta', {})}")

        yield client, base_url, getattr(cfg, "unifi_site", "default") or "default"

        # Logout (best-effort)
        try:
            client.get("/api/logout")
        except Exception:
            pass


# ── Tools ──────────────────────────────────────────────────────────────────────

@tool
def query_unifi_clients(
    include_inactive: bool = False,
) -> str:
    """Get connected client list from UniFi Controller.

    Returns all currently associated wireless clients with MAC address,
    IP, AP name, signal strength, RSSI, VLAN, hostname, and auth status.
    Useful for identifying unknown devices, weak-signal clients, and
    clients failing authentication.

    Args:
        include_inactive: Include recently disconnected clients (default: False)

    Returns:
        JSON with client count, AP summary, and per-client details.
    """
    cfg = get_config()
    if not getattr(cfg, "unifi_host", None):
        return json.dumps({"error": "UNIFI_HOST not configured in .env — set UNIFI_HOST, UNIFI_USERNAME, UNIFI_PASSWORD"})

    try:
        with _unifi_client() as (client, base_url, site):
            endpoint = f"/api/s/{site}/stat/sta"
            resp = client.get(endpoint)
            if resp.status_code != 200:
                return json.dumps({"error": f"HTTP {resp.status_code}", "body": resp.text[:200]})

            data = resp.json()
            if data.get("meta", {}).get("rc") != "ok":
                return json.dumps({"error": f"Controller error: {data.get('meta')}"})

            clients_raw = data.get("data", [])

    except RuntimeError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        logger.error("UniFi client query failed: %s", e)
        return json.dumps({"error": str(e)})

    clients = []
    ap_client_counts: dict = {}

    for c in clients_raw:
        # Skip inactive if not requested
        if not include_inactive and not c.get("is_wired", False) and not c.get("essid"):
            continue

        ap_mac = c.get("ap_mac", "")
        ap_name = c.get("ap_name", ap_mac)
        ap_client_counts[ap_name] = ap_client_counts.get(ap_name, 0) + 1

        signal = c.get("signal")  # dBm
        noise = c.get("noise")    # dBm
        snr = (signal - noise) if signal and noise else None

        clients.append({
            "mac": c.get("mac", ""),
            "hostname": c.get("hostname") or c.get("name") or "",
            "ip": c.get("ip", ""),
            "essid": c.get("essid", ""),
            "ap_name": ap_name,
            "vlan": c.get("vlan", 0),
            "signal_dbm": signal,
            "snr_db": round(snr, 1) if snr else None,
            "tx_rate_mbps": round((c.get("tx_rate", 0) or 0) / 1000, 1),
            "rx_rate_mbps": round((c.get("rx_rate", 0) or 0) / 1000, 1),
            "tx_bytes": c.get("tx_bytes", 0),
            "rx_bytes": c.get("rx_bytes", 0),
            "uptime_s": c.get("uptime", 0),
            "is_wired": c.get("is_wired", False),
            "auth_failures": c.get("assoc_fails", 0),
            "blocked": c.get("blocked", False),
            "oui": c.get("oui", ""),
        })

    # Sort by AP name then hostname
    clients.sort(key=lambda x: (x["ap_name"], x["hostname"]))

    # Flag clients with auth failures
    auth_failure_clients = [c for c in clients if c.get("auth_failures", 0) > 0]

    return json.dumps({
        "total_clients": len(clients),
        "ap_client_counts": ap_client_counts,
        "auth_failure_clients": auth_failure_clients,
        "clients": clients,
    }, indent=2)


@tool
def query_unifi_ap_stats() -> str:
    """Get UniFi AP statistics: per-AP client count, channel utilization, and health.

    Returns all access points with their radio config, channel, TX power,
    connected client count, and any reported issues. Useful for identifying
    overloaded APs, RF interference, or offline APs.

    Returns:
        JSON with AP list including status, radio config, client counts, and alerts.
    """
    cfg = get_config()
    if not getattr(cfg, "unifi_host", None):
        return json.dumps({"error": "UNIFI_HOST not configured in .env — set UNIFI_HOST, UNIFI_USERNAME, UNIFI_PASSWORD"})

    try:
        with _unifi_client() as (client, base_url, site):
            resp = client.get(f"/api/s/{site}/stat/device")
            if resp.status_code != 200:
                return json.dumps({"error": f"HTTP {resp.status_code}", "body": resp.text[:200]})

            data = resp.json()
            if data.get("meta", {}).get("rc") != "ok":
                return json.dumps({"error": f"Controller error: {data.get('meta')}"})

            devices_raw = data.get("data", [])

    except RuntimeError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        logger.error("UniFi AP stats query failed: %s", e)
        return json.dumps({"error": str(e)})

    aps = []
    alerts = []

    for dev in devices_raw:
        if dev.get("type") not in ("uap", "ugw", "usw"):
            continue

        state = dev.get("state", 0)
        connected = state == 1
        name = dev.get("name") or dev.get("mac", "unknown")

        if not connected:
            alerts.append(f"AP {name} is offline (state={state})")

        # Radio table
        radios = []
        for rt in dev.get("radio_table_stats", dev.get("radio_table", [])):
            radio_info = {
                "name": rt.get("name", ""),
                "channel": rt.get("channel"),
                "tx_power": rt.get("tx_power"),
                "num_sta": rt.get("num_sta", 0),
                "cu_self_rx": rt.get("cu_self_rx"),  # channel util: own RX
                "cu_self_tx": rt.get("cu_self_tx"),  # channel util: own TX
                "cu_other": rt.get("cu_other"),       # interference from others
            }
            radios.append(radio_info)

            # Flag high channel utilization
            total_cu = (rt.get("cu_self_rx", 0) or 0) + (rt.get("cu_self_tx", 0) or 0) + (rt.get("cu_other", 0) or 0)
            if total_cu > 70:
                alerts.append(f"AP {name} radio {rt.get('name')} high channel utilization: {total_cu}%")

        aps.append({
            "name": name,
            "mac": dev.get("mac", ""),
            "ip": dev.get("ip", ""),
            "model": dev.get("model", ""),
            "version": dev.get("version", ""),
            "connected": connected,
            "uptime_s": dev.get("uptime", 0),
            "num_sta": dev.get("num_sta", 0),
            "user_num_sta": dev.get("user-num_sta", 0),
            "radios": radios,
            "load_avg_1m": dev.get("sys_stats", {}).get("loadavg_1"),
            "mem_pct": round(
                dev.get("sys_stats", {}).get("mem_used", 0) /
                max(dev.get("sys_stats", {}).get("mem_total", 1), 1) * 100, 1
            ) if dev.get("sys_stats") else None,
        })

    aps.sort(key=lambda x: x["name"])

    return json.dumps({
        "total_aps": len(aps),
        "online_aps": sum(1 for a in aps if a["connected"]),
        "alerts": alerts,
        "aps": aps,
    }, indent=2)
