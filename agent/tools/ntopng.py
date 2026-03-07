"""
Tools for querying ntopng REST API for flow data and network statistics.

All endpoints verified against ntopng v6.7 REST API v2 Swagger specification.
Tested with ntopng Community Edition.
"""

import httpx
import json
from typing import Optional, Literal
from urllib.parse import urlencode

from langchain_core.tools import tool

from agent.config import get_config


@tool
def query_ntopng_interfaces() -> str:
    """Get list of network interfaces monitored by ntopng.

    Returns:
        JSON with interface names, IDs, and basic stats
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/ntopng/interfaces.lua"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                auth=(config.ntopng_username or "", config.ntopng_password or "")
            )

            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            return response.text

    except httpx.TimeoutException:
        return "Error: Request timed out after 10 seconds"
    except Exception as e:
        return f"Error querying ntopng: {str(e)}"


@tool
def query_ntopng_active_hosts(
    ifid: int = 3,
    currentPage: int = 1,
    perPage: int = 20,
    sortColumn: str = "bytes",
    sortOrder: str = "desc"
) -> str:
    """Get list of active hosts with traffic statistics.

    This replaces the non-existent 'top_talkers' endpoint.

    Args:
        ifid: Interface ID (default: 3 for eth0)
        currentPage: Page number for pagination (default: 1)
        perPage: Results per page (default: 20)
        sortColumn: Sort by field - bytes, packets, name (default: bytes)
        sortOrder: Sort direction - asc or desc (default: desc)

    Returns:
        JSON with active hosts list including traffic stats, IPs, MACs
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    params = {
        "ifid": ifid,
        "currentPage": currentPage,
        "perPage": perPage,
        "sortColumn": sortColumn,
        "sortOrder": sortOrder
    }

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/host/active.lua?{urlencode(params)}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                auth=(config.ntopng_username or "", config.ntopng_password or "")
            )

            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            return response.text

    except httpx.TimeoutException:
        return "Error: Request timed out after 10 seconds"
    except Exception as e:
        return f"Error querying ntopng: {str(e)}"


@tool
def query_ntopng_interface_stats(ifid: int = 3) -> str:
    """Get detailed statistics for a specific network interface.

    Args:
        ifid: Interface ID (default: 3 for eth0)

    Returns:
        JSON with interface stats (bytes, packets, active hosts, flows)
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/interface/data.lua?ifid={ifid}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                auth=(config.ntopng_username or "", config.ntopng_password or "")
            )

            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            return response.text

    except httpx.TimeoutException:
        return "Error: Request timed out after 10 seconds"
    except Exception as e:
        return f"Error querying ntopng: {str(e)}"


@tool
def query_ntopng_alerts(
    ifid: Optional[int] = 3,
    currentPage: int = 1,
    perPage: int = 50,
    severity: Optional[str] = None
) -> str:
    """Get list of all alerts from ntopng.

    Args:
        ifid: Interface ID to filter by (default: 3, use None for all interfaces)
        currentPage: Page number for pagination (default: 1)
        perPage: Results per page (default: 50)
        severity: Alert severity filter - error, warning, info (optional)

    Returns:
        JSON with alerts list including type, severity, affected entities
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    params = {
        "currentPage": currentPage,
        "perPage": perPage
    }

    if ifid is not None:
        params["ifid"] = ifid
    if severity:
        params["severity"] = severity

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/all/alert/list.lua?{urlencode(params)}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                auth=(config.ntopng_username or "", config.ntopng_password or "")
            )

            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            return response.text

    except httpx.TimeoutException:
        return "Error: Request timed out after 10 seconds"
    except Exception as e:
        return f"Error querying ntopng: {str(e)}"


@tool
def query_ntopng_host_details(
    host: str,
    ifid: int = 3
) -> str:
    """Get detailed information about a specific host.

    Args:
        host: IP address or hostname to query
        ifid: Interface ID (default: 3 for eth0)

    Returns:
        JSON with host details (traffic stats, active flows, protocols)
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    params = {
        "host": host,
        "ifid": ifid
    }

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/host/data.lua?{urlencode(params)}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                auth=(config.ntopng_username or "", config.ntopng_password or "")
            )

            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            return response.text

    except httpx.TimeoutException:
        return "Error: Request timed out after 10 seconds"
    except Exception as e:
        return f"Error querying ntopng: {str(e)}"


@tool
def query_ntopng_active_flows(
    ifid: int = 3,
    currentPage: int = 1,
    perPage: int = 20,
    sortColumn: str = "bytes",
    sortOrder: str = "desc"
) -> str:
    """Get list of active network flows.

    Args:
        ifid: Interface ID (default: 3 for eth0)
        currentPage: Page number for pagination (default: 1)
        perPage: Results per page (default: 20)
        sortColumn: Sort by field - bytes, packets, duration (default: bytes)
        sortOrder: Sort direction - asc or desc (default: desc)

    Returns:
        JSON with active flows including client/server IPs, ports, protocols, throughput
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    params = {
        "ifid": ifid,
        "currentPage": currentPage,
        "perPage": perPage,
        "sortColumn": sortColumn,
        "sortOrder": sortOrder
    }

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/flow/active.lua?{urlencode(params)}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                auth=(config.ntopng_username or "", config.ntopng_password or "")
            )

            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            return response.text

    except httpx.TimeoutException:
        return "Error: Request timed out after 10 seconds"
    except Exception as e:
        return f"Error querying ntopng: {str(e)}"


@tool
def query_ntopng_l7_protocols(ifid: int = 3) -> str:
    """Get Layer 7 (application) protocol traffic counters.

    Args:
        ifid: Interface ID (default: 3 for eth0)

    Returns:
        JSON with traffic breakdown by application protocol (HTTP, DNS, TLS, SSH, etc.)
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/flow/l7/counters.lua?ifid={ifid}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                auth=(config.ntopng_username or "", config.ntopng_password or "")
            )

            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            return response.text

    except httpx.TimeoutException:
        return "Error: Request timed out after 10 seconds"
    except Exception as e:
        return f"Error querying ntopng: {str(e)}"


@tool
def query_ntopng_arp_table(ifid: int = 3) -> str:
    """Get the ARP (Address Resolution Protocol) table.

    Shows mapping between IP addresses and MAC addresses on the network.

    Args:
        ifid: Interface ID (default: 3 for eth0)

    Returns:
        JSON with ARP entries (IP to MAC mappings)
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/interface/arp.lua?ifid={ifid}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                auth=(config.ntopng_username or "", config.ntopng_password or "")
            )

            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            return response.text

    except httpx.TimeoutException:
        return "Error: Request timed out after 10 seconds"
    except Exception as e:
        return f"Error querying ntopng: {str(e)}"


@tool
def query_ntopng_host_l7_stats(
    host: str,
    ifid: int = 3
) -> str:
    """Get Layer 7 protocol statistics for a specific host.

    Args:
        host: IP address or hostname to query
        ifid: Interface ID (default: 3 for eth0)

    Returns:
        JSON with L7 protocol breakdown for the host
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    params = {
        "host": host,
        "ifid": ifid
    }

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/host/l7/stats.lua?{urlencode(params)}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                url,
                auth=(config.ntopng_username or "", config.ntopng_password or "")
            )

            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            return response.text

    except httpx.TimeoutException:
        return "Error: Request timed out after 10 seconds"
    except Exception as e:
        return f"Error querying ntopng: {str(e)}"
