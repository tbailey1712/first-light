"""
Active device inventory via ntopng ARP table + host data.

Uses ntopng's ARP table as the source of truth for active devices — it sees
every host regardless of whether they have a DHCP lease (static IPs, VPN
clients, etc.). Enriches with MAC vendor lookup and ntopng host stats.
"""

import json
import logging

import httpx
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# OUI → vendor cache to avoid repeated API calls
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


@tool
def query_active_device_inventory(vlan: int = 0) -> str:
    """Get all active network devices with MAC, vendor, OS fingerprint, score and flow stats.

    Uses ntopng's ARP table as the device source — captures every active host
    including those with static IPs or not in DHCP. Useful for spotting unknown
    devices, identifying IoT clients, and getting device fingerprints.

    Args:
        vlan: Filter by VLAN ID (0 = all VLANs, 1=trusted, 2=IoT, 3=CCTV, 4=DMZ)

    Returns:
        JSON with devices sorted by risk score, each including ip, mac, hostname,
        vendor, vlan, ntopng_score, ntopng_flows, ntopng_bytes, ntopng_os.
    """
    from agent.tools.ntopng import _ntopng_client, get_config

    config = get_config()
    if not config.ntopng_host:
        return json.dumps({"error": "ntopng_host not configured"})

    try:
        with _ntopng_client() as (client, host):
            # Get ARP table for MAC addresses
            arp_r = client.get(f"{host}/lua/rest/v2/get/arp/table.lua", params={"ifid": 3})
            arp_table = {}
            if arp_r.status_code == 200:
                arp_data = arp_r.json().get("rsp", [])
                if isinstance(arp_data, list):
                    for entry in arp_data:
                        ip = entry.get("ip", "")
                        if ip:
                            arp_table[ip] = entry.get("mac", "")

        # Fetch active hosts in a separate connection (ntopng closes session after each)
        with _ntopng_client() as (client, host):
            hosts_r = client.get(f"{host}/lua/rest/v2/get/host/active.lua", params={
                "ifid": 3, "perPage": 200, "currentPage": 1,
                "sortColumn": "score", "sortOrder": "desc",
            })
            if hosts_r.status_code != 200:
                return json.dumps({"error": f"ntopng hosts HTTP {hosts_r.status_code}"})

            data = hosts_r.json().get("rsp", {})
            hosts = data.get("data", []) if isinstance(data, dict) else []

    except Exception as e:
        return json.dumps({"error": f"ntopng query failed: {e}"})

    devices = []
    seen_ips = set()

    for h in hosts:
        ip = h.get("ip", "")
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)

        host_vlan = h.get("vlan", 0)
        if vlan and host_vlan != vlan:
            continue

        mac = arp_table.get(ip, h.get("mac", ""))
        vendor = _lookup_vendor(mac) if mac else "Unknown"

        bytes_data = h.get("bytes", {})
        bytes_total = bytes_data.get("total", 0) if isinstance(bytes_data, dict) else 0

        score_data = h.get("score", {})
        score = score_data.get("total", 0) if isinstance(score_data, dict) else 0

        flows_data = h.get("num_flows", {})
        flows = flows_data.get("total", 0) if isinstance(flows_data, dict) else 0

        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": h.get("name", ""),
            "vendor": vendor,
            "vlan": host_vlan,
            "ntopng_score": score,
            "ntopng_flows": flows,
            "ntopng_bytes": bytes_total,
            "ntopng_os": h.get("os_detail", ""),
            "is_blacklisted": h.get("is_blacklisted", False),
        })

    devices.sort(key=lambda d: d["ntopng_score"], reverse=True)

    return json.dumps({"total": len(devices), "devices": devices}, indent=2)
