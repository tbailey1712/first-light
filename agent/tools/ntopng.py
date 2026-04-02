"""
Tools for querying ntopng REST API for flow data and network statistics.

All endpoints verified against ntopng v6.7 REST API v2 Swagger specification.
Tested with ntopng Community Edition.

Auth: ntopng v6 requires session cookie auth (Basic Auth returns 302).
      _ntopng_client() handles login and returns an authenticated httpx.Client.
"""

import httpx
import json
from contextlib import contextmanager
from typing import Optional
from urllib.parse import urlencode

from langchain_core.tools import tool

from agent.config import get_config


@contextmanager
def _ntopng_client():
    """Yield an httpx.Client authenticated to ntopng via session cookie."""
    config = get_config()
    host = f"http://{config.ntopng_host}:{config.ntopng_port}"

    with httpx.Client(timeout=15.0, follow_redirects=True) as client:
        resp = client.post(
            f"{host}/authorize.html",
            data={
                "user": config.ntopng_username or "admin",
                "password": config.ntopng_password or "",
            },
        )
        if resp.status_code != 200:
            raise RuntimeError(f"ntopng login failed: HTTP {resp.status_code}")
        yield client, host


def _get(path: str, params: Optional[dict] = None) -> str:
    """Authenticated GET against ntopng REST API. Returns response text."""
    try:
        with _ntopng_client() as (client, host):
            r = client.get(f"{host}{path}", params=params)
            if r.status_code != 200:
                return json.dumps({"error": f"HTTP {r.status_code}", "body": r.text[:200]})
            return r.text
    except Exception as e:
        return json.dumps({"error": str(e)})


# ── Tools ──────────────────────────────────────────────────────────────────────

@tool
def query_ntopng_interfaces() -> str:
    """Get list of network interfaces monitored by ntopng.

    Returns:
        JSON with interface names, IDs, and basic stats.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    return _get("/lua/rest/v2/get/ntopng/interfaces.lua")


@tool
def query_ntopng_active_hosts(
    ifid: int = 3,
    currentPage: int = 1,
    perPage: int = 20,
    sortColumn: str = "bytes",
    sortOrder: str = "desc",
) -> str:
    """Get active hosts sorted by traffic volume.

    Args:
        ifid: Interface ID (default: 3 for eth0)
        currentPage: Page number (default: 1)
        perPage: Results per page (default: 20)
        sortColumn: Sort by bytes, packets, or name (default: bytes)
        sortOrder: asc or desc (default: desc)

    Returns:
        JSON with active hosts including traffic stats and IPs.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    return _get("/lua/rest/v2/get/host/active.lua", {
        "ifid": ifid, "currentPage": currentPage,
        "perPage": perPage, "sortColumn": sortColumn, "sortOrder": sortOrder,
    })


@tool
def query_ntopng_interface_stats(ifid: int = 3) -> str:
    """Get traffic and flow statistics for a network interface.

    Args:
        ifid: Interface ID (default: 3 for eth0)

    Returns:
        JSON with bytes, packets, active hosts, flows, and alert counters.
        NOTE: dropped_alerts and written_alerts are CUMULATIVE counters since
        ntopng last restarted — they are NOT 24-hour counts. Do not alarm on
        their absolute values; only the delta between runs is meaningful.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    raw = _get("/lua/rest/v2/get/interface/data.lua", {"ifid": ifid})
    # Annotate cumulative counters so the LLM does not misinterpret them
    try:
        data = json.loads(raw)
        rsp = data.get("rsp", data)
        for key in ("dropped_alerts", "written_alerts", "alerts_queries"):
            if key in rsp:
                rsp[f"{key}_NOTE"] = "cumulative since ntopng last restart, NOT a 24h count"
        # Packet drops are ntopng PROCESSING drops (packets ntopng couldn't keep up with),
        # NOT actual network packet loss. Real loss shows in switch/router SNMP counters.
        for key in ("dropped_packets", "in_pkts_drop_percentage", "out_pkts_drop_percentage",
                    "drops", "drop_percentage"):
            if key in rsp:
                rsp[f"{key}_NOTE"] = (
                    "ntopng internal processing drops — packets ntopng could not analyze "
                    "fast enough. This is NOT real network packet loss. "
                    "Do NOT report this as a network problem."
                )
        return json.dumps(data)
    except (json.JSONDecodeError, TypeError):
        return raw


@tool
def query_ntopng_alerts(
    ifid: int = 3,
    currentPage: int = 1,
    perPage: int = 20,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
) -> str:
    """Get active (engaged) alerts from ntopng, with interface summary as fallback.

    ntopng CE stores alert counts in memory (alerted_flows, num_local_hosts_anomalies)
    but only persists engaged/active alerts to the API. Historical flow alerts are
    not available via API in Community Edition.

    Args:
        ifid: Interface ID (default: 3)
        currentPage: Page number (default: 1)
        perPage: Results per page — keep low to avoid 500 under load (default: 20)
        severity: Filter by severity: emergency, alert, critical, error, warning, notice, info, debug
        alert_type: Optional alert type name to filter (e.g. 'flow_flood')

    Returns:
        JSON with engaged alerts if available, or interface-level alert summary counts.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    params: dict = {
        "ifid": ifid,
        "currentPage": currentPage,
        "perPage": perPage,
        "status": "engaged",
    }
    if severity:
        params["severity"] = severity
    if alert_type:
        params["alert_type"] = alert_type

    result = _get("/lua/rest/v2/get/all/alert/list.lua", params)

    try:
        parsed = json.loads(result)
        if "error" not in parsed and parsed.get("rc", -1) == 0:
            return result  # success path
    except (json.JSONDecodeError, TypeError):
        pass

    # Alert list endpoint failed or returned error — fall back to interface stats summary.
    # ntopng CE doesn't persist historical flow alerts; the in-memory counters are the
    # best available data when the list endpoint is unavailable.
    iface_raw = _get("/lua/rest/v2/get/interface/data.lua", {"ifid": ifid})
    try:
        iface = json.loads(iface_raw)
        rsp = iface.get("rsp", iface)
        return json.dumps({
            "WARNING": (
                "TOOL DEGRADED: ntopng alert list endpoint failed (HTTP 500 or CE limitation). "
                "Detailed per-alert data is unavailable. Reporting interface-level counters only. "
                "Recommend manual review of ntopng UI for individual alert details."
            ),
            "alerted_flows_cumulative": rsp.get("alerted_flows", "unknown"),
            "engaged_alerts_now": rsp.get("engaged_alerts", "unknown"),
            "local_host_anomalies_cumulative": rsp.get("num_local_hosts_anomalies", "unknown"),
            "alert_list_raw_error": result,
        })
    except Exception:
        return result


@tool
def query_ntopng_host_details(host: str, ifid: int = 3) -> str:
    """Get detailed traffic and flow information for a specific host.

    Args:
        host: IP address to query
        ifid: Interface ID (default: 3)

    Returns:
        JSON with host traffic stats, active flows, and protocol breakdown.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    return _get("/lua/rest/v2/get/host/data.lua", {"host": host, "ifid": ifid})


@tool
def query_ntopng_active_flows(
    ifid: int = 3,
    currentPage: int = 1,
    perPage: int = 20,
    sortColumn: str = "bytes",
    sortOrder: str = "desc",
) -> str:
    """Get active network flows sorted by volume.

    Args:
        ifid: Interface ID (default: 3)
        currentPage: Page number (default: 1)
        perPage: Results per page (default: 20)
        sortColumn: Sort by bytes, packets, or duration (default: bytes)
        sortOrder: asc or desc (default: desc)

    Returns:
        JSON with active flows including client/server IPs, ports, protocols.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    return _get("/lua/rest/v2/get/flow/active.lua", {
        "ifid": ifid, "currentPage": currentPage,
        "perPage": perPage, "sortColumn": sortColumn, "sortOrder": sortOrder,
    })


@tool
def query_ntopng_l7_protocols(ifid: int = 3) -> str:
    """Get Layer 7 application protocol traffic counters.

    Args:
        ifid: Interface ID (default: 3)

    Returns:
        JSON with traffic breakdown by application protocol (HTTP, DNS, TLS, etc.)
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    return _get("/lua/rest/v2/get/flow/l7/counters.lua", {"ifid": ifid})


@tool
def query_ntopng_arp_table(ifid: int = 3) -> str:
    """Get the ARP table showing IP-to-MAC mappings.

    Args:
        ifid: Interface ID (default: 3)

    Returns:
        JSON with ARP entries.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    return _get("/lua/rest/v2/get/interface/arp.lua", {"ifid": ifid})


@tool
def query_ntopng_vlan_traffic(ifid: int = 3) -> str:
    """Get traffic breakdown by VLAN on a network interface.

    Critical for detecting cross-VLAN anomalies — e.g. Camera VLAN (3) or
    Validator VLAN (4) talking to unexpected destinations.

    Args:
        ifid: Interface ID (default: 3)

    Returns:
        JSON with per-VLAN bytes, packets, and flow counts.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    return _get("/lua/rest/v2/get/vlan/list.lua", {"ifid": ifid})


@tool
def query_ntopng_top_countries(ifid: int = 3, limit: int = 20) -> str:
    """Get top traffic sources/destinations by country.

    Useful for identifying unexpected geographic traffic patterns —
    e.g. high outbound to unusual countries may indicate C2 activity.

    Args:
        ifid: Interface ID (default: 3)
        limit: Max countries to return (default: 20)

    Returns:
        JSON with per-country bytes in/out and flow counts.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    result = _get("/lua/rest/v2/get/host/country/list.lua", {"ifid": ifid})
    # Gracefully handle Enterprise-only response
    try:
        parsed = json.loads(result)
        if isinstance(parsed, dict) and parsed.get("rc", 0) < 0:
            return json.dumps({"note": "Country traffic data not available in ntopng Community Edition"})
    except (json.JSONDecodeError, TypeError):
        pass
    return result


@tool
def query_ntopng_host_l7_stats(host: str, ifid: int = 3) -> str:
    """Get Layer 7 protocol breakdown for a specific host.

    Args:
        host: IP address to query
        ifid: Interface ID (default: 3)

    Returns:
        JSON with L7 protocol stats for the host.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    return _get("/lua/rest/v2/get/host/l7/stats.lua", {"host": host, "ifid": ifid})
