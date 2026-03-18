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
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    return _get("/lua/rest/v2/get/interface/data.lua", {"ifid": ifid})


@tool
def query_ntopng_alerts(
    ifid: int = 3,
    currentPage: int = 1,
    perPage: int = 30,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
) -> str:
    """Get alerts from ntopng, filtered by severity.

    Args:
        ifid: Interface ID (default: 3)
        currentPage: Page number (default: 1)
        perPage: Results per page — keep low to avoid timeout (default: 30)
        severity: Filter by severity: emergency, alert, critical, error, warning, notice, info, debug
        alert_type: Optional alert type name to filter (e.g. 'flow_flood')

    Returns:
        JSON with alert list including type, severity, and affected entities.
    """
    config = get_config()
    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"
    params: dict = {"ifid": ifid, "currentPage": currentPage, "perPage": perPage}
    if severity:
        params["severity"] = severity
    if alert_type:
        params["alert_type"] = alert_type
    return _get("/lua/rest/v2/get/all/alert/list.lua", params)


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
