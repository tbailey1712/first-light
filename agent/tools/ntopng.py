"""
Tools for querying ntopng REST API for flow data and network statistics.

NOTE: Some endpoints require ntopng Enterprise Edition and may not work
with Community Edition. Tested working endpoints:
- query_ntopng_interfaces()
- query_ntopng_interface_stats()
- query_ntopng_flow_summary()
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
def query_ntopng_top_talkers(
    ifid: int = 3,
    limit: int = 20,
    sortby: str = "bytes"
) -> str:
    """Get top bandwidth users (top talkers) from ntopng.

    NOTE: This endpoint may not be available in ntopng Community Edition.

    Args:
        ifid: Interface ID (default: 3 for eth0)
        limit: Number of results to return (default: 20)
        sortby: Sort field (bytes, packets, flows) (default: bytes)

    Returns:
        JSON with top hosts by traffic volume
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    params = {
        "ifid": ifid,
        "limit": limit,
        "sortby": sortby
    }

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/host/top_talkers.lua?{urlencode(params)}"

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
def query_ntopng_active_alerts(
    ifid: Optional[int] = None,
    severity: Optional[str] = None
) -> str:
    """Get currently active/engaged alerts from ntopng.

    Args:
        ifid: Interface ID to filter by (optional, all interfaces if not specified)
        severity: Alert severity filter (error, warning, info) (optional)

    Returns:
        JSON with active alerts including type, severity, affected hosts
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    params = {}
    if ifid is not None:
        params["ifid"] = ifid
    if severity:
        params["severity"] = severity

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/alert/list_engaged.lua"
    if params:
        url += f"?{urlencode(params)}"

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
        JSON with host details (traffic stats, active flows, alerts)
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
def query_ntopng_flow_summary(
    ifid: int = 3,
    protocol: Optional[str] = None
) -> str:
    """Get summary of active network flows.

    Args:
        ifid: Interface ID (default: 3 for eth0)
        protocol: Filter by protocol (TCP, UDP, ICMP) (optional)

    Returns:
        JSON with active flows summary by protocol, application, hosts
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    params = {"ifid": ifid}
    if protocol:
        params["protocol"] = protocol

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
    """Get Layer 7 (application) protocol breakdown.

    NOTE: This endpoint may not be available in ntopng Community Edition.

    Args:
        ifid: Interface ID (default: 3 for eth0)

    Returns:
        JSON with traffic breakdown by application protocol (HTTP, DNS, TLS, SSH, etc.)
    """
    config = get_config()

    if not config.ntopng_host:
        return "Error: ntopng_host not configured in .env"

    url = f"http://{config.ntopng_host}:{config.ntopng_port}/lua/rest/v2/get/interface/l7/stats.lua?ifid={ifid}"

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
