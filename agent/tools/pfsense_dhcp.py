"""
pfSense DHCP lease inventory with ntopng enrichment.

Fetches all DHCP leases from pfSense, cross-references with ntopng active
hosts, and returns a per-device inventory with vendor, OS fingerprint, score,
and flow count. Useful for spotting unknown/unrecognised devices.
"""

import json
import logging
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)

# Simple OUI prefix → vendor cache to avoid repeated API calls
_OUI_CACHE: dict[str, str] = {}


def _lookup_vendor(mac: str) -> str:
    """Look up MAC vendor via macvendors.com API with local cache."""
    if not mac or len(mac) < 8:
        return "Unknown"
    oui = mac[:8].upper()
    if oui in _OUI_CACHE:
        return _OUI_CACHE[oui]
    try:
        r = httpx.get(f"https://api.macvendors.com/{oui}", timeout=5)
        vendor = r.text.strip() if r.status_code == 200 else "Unknown"
    except Exception:
        vendor = "Unknown"
    _OUI_CACHE[oui] = vendor
    return vendor


def _get_ntopng_hosts() -> dict[str, dict]:
    """Fetch active ntopng hosts, keyed by IP."""
    try:
        from agent.tools.ntopng import _ntopng_client, get_config as _cfg
        config = _cfg()
        if not config.ntopng_host:
            return {}
        with _ntopng_client() as (client, host):
            r = client.get(f"{host}/lua/rest/v2/get/host/active.lua", params={
                "ifid": 3, "perPage": 200, "currentPage": 1,
                "sortColumn": "bytes", "sortOrder": "desc",
            })
            if r.status_code != 200:
                return {}
            data = r.json().get("rsp", {})
            hosts = data.get("data", []) if isinstance(data, dict) else []
            result = {}
            for h in hosts:
                ip = h.get("ip", "")
                if ip and ip not in result:
                    result[ip] = h
            return result
    except Exception as e:
        logger.warning("ntopng host fetch failed: %s", e)
        return {}


@tool
def query_dhcp_device_inventory(active_only: bool = True) -> str:
    """Get all DHCP-registered devices with vendor, OS fingerprint, and activity stats.

    Cross-references pfSense DHCP leases with ntopng active host data to build
    a full inventory of known devices. Use this to spot unknown devices, identify
    what IoT/DHCP clients are doing, and get device fingerprints.

    Args:
        active_only: If True, only return devices seen by ntopng in the past 24h (default: True)

    Returns:
        JSON array of devices with ip, mac, hostname, vendor, ntopng_score,
        ntopng_flows, ntopng_os, ntopng_bytes_total, active_24h fields.
    """
    config = get_config()

    # Fetch pfSense DHCP leases
    leases = []
    if config.pfsense_host and config.pfsense_api_key:
        try:
            auth_header = f"{config.pfsense_api_key} {config.pfsense_api_secret or ''}".strip()
            r = httpx.get(
                f"https://{config.pfsense_host}/api/v1/services/dhcpv4/leases",
                headers={"Authorization": auth_header},
                verify=False,
                timeout=10,
            )
            if r.status_code == 200:
                leases = r.json().get("data", [])
                logger.info("pfSense DHCP: %d leases fetched", len(leases))
            else:
                logger.warning("pfSense DHCP API: HTTP %d", r.status_code)
        except Exception as e:
            logger.warning("pfSense DHCP fetch failed: %s", e)

    if not leases:
        return json.dumps({"error": "No DHCP leases available — check pfSense API config (PFSENSE_HOST, PFSENSE_API_KEY)"})

    # Fetch ntopng hosts for enrichment
    ntopng_hosts = _get_ntopng_hosts()

    devices = []
    for lease in leases:
        ip = lease.get("ip", "")
        mac = lease.get("mac", "")
        hostname = lease.get("hostname", "") or lease.get("descr", "")
        state = lease.get("state", "")

        ntopng = ntopng_hosts.get(ip, {})
        active = bool(ntopng)

        if active_only and not active:
            continue

        bytes_data = ntopng.get("bytes", {})
        bytes_total = bytes_data.get("total", 0) if isinstance(bytes_data, dict) else 0

        score_data = ntopng.get("score", {})
        score = score_data.get("total", 0) if isinstance(score_data, dict) else 0

        flows_data = ntopng.get("num_flows", {})
        flows = flows_data.get("total", 0) if isinstance(flows_data, dict) else 0

        vendor = _lookup_vendor(mac) if mac else "Unknown"

        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname or ntopng.get("name", ""),
            "vendor": vendor,
            "lease_state": state,
            "active_24h": active,
            "ntopng_score": score,
            "ntopng_flows": flows,
            "ntopng_bytes_total": bytes_total,
            "ntopng_os": ntopng.get("os_detail", ""),
            "vlan": ntopng.get("vlan", 0),
        })

    # Sort by score descending so high-risk devices surface first
    devices.sort(key=lambda d: d["ntopng_score"], reverse=True)

    return json.dumps({"total": len(devices), "devices": devices}, indent=2)
