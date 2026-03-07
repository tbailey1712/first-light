#!/usr/bin/env python3
"""
DNS Security MCP Server (FastMCP + HTTP)

Exposes First Light DNS security tools via Model Context Protocol over HTTP.
Runs as a containerized service in docker-compose, accessible on port 8080.

Usage:
    python mcp_servers/dns_security.py

    Or via docker-compose:
    docker-compose up -d mcp-server

    Then access at: http://localhost:8080

Environment:
    Requires SigNoz credentials in .env or environment variables
"""

import os
import sys
from typing import Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from fastmcp import FastMCP

# Import DNS tools
from agent.tools.logs import (
    query_security_summary,
    query_adguard_anomalies,
    query_wireless_health,
    query_infrastructure_events,
    search_logs_by_ip,
)
from agent.tools.metrics import (
    query_adguard_top_clients,
    query_adguard_block_rates,
    query_adguard_high_risk_clients,
    query_adguard_blocked_domains,
    query_adguard_traffic_by_type,
)


# Create FastMCP server
mcp = FastMCP("DNS Security")


# === Register Tools ===

@mcp.tool()
def top_dns_clients(hours: int = 24, limit: int = 20) -> str:
    """Get top DNS clients by query volume.

    Args:
        hours: Lookback period in hours (default: 24)
        limit: Number of results (default: 20)
    """
    return query_adguard_top_clients.invoke({"hours": hours, "limit": limit})


@mcp.tool()
def dns_block_rates(hours: int = 24, min_block_rate: float = 0.0, limit: int = 20) -> str:
    """Get DNS block rates per client.

    Args:
        hours: Lookback period in hours (default: 24)
        min_block_rate: Minimum block rate threshold (default: 0.0)
        limit: Number of results (default: 20)
    """
    return query_adguard_block_rates.invoke({
        "hours": hours,
        "min_block_rate": min_block_rate,
        "limit": limit
    })


@mcp.tool()
def high_risk_clients(hours: int = 24, min_risk_score: float = 5.0, limit: int = 20) -> str:
    """Get high-risk DNS clients with suspicious activity.

    Args:
        hours: Lookback period in hours (default: 24)
        min_risk_score: Minimum risk score threshold (default: 5.0, max: 10.0)
        limit: Number of results (default: 20)
    """
    return query_adguard_high_risk_clients.invoke({
        "hours": hours,
        "min_risk_score": min_risk_score,
        "limit": limit
    })


@mcp.tool()
def blocked_domains(hours: int = 24, limit: int = 50) -> str:
    """Get most frequently blocked domains.

    Args:
        hours: Lookback period in hours (default: 24)
        limit: Number of results (default: 50)
    """
    return query_adguard_blocked_domains.invoke({"hours": hours, "limit": limit})


@mcp.tool()
def dns_traffic_by_type(hours: int = 24) -> str:
    """Get DNS query volume breakdown by response type.

    Args:
        hours: Lookback period in hours (default: 24)
    """
    return query_adguard_traffic_by_type.invoke({"hours": hours})


@mcp.tool()
def security_summary(hours: int = 1) -> str:
    """Get security summary showing threats, blocks, and attacks.

    Args:
        hours: Lookback period in hours (default: 1, max: 24)
    """
    return query_security_summary.invoke({"hours": min(hours, 24)})


@mcp.tool()
def dns_anomalies(hours: int = 1, limit: int = 20) -> str:
    """Get DNS anomalies and unusual patterns.

    Args:
        hours: Lookback period in hours (default: 1)
        limit: Number of results (default: 20)
    """
    return query_adguard_anomalies.invoke({"hours": hours, "limit": limit})


@mcp.tool()
def wireless_health(hours: int = 1) -> str:
    """Get wireless network health summary.

    Args:
        hours: Lookback period in hours (default: 1)
    """
    return query_wireless_health.invoke({"hours": hours})


@mcp.tool()
def infrastructure_events(hours: int = 1, limit: int = 50) -> str:
    """Get infrastructure events and alerts.

    Args:
        hours: Lookback period in hours (default: 1)
        limit: Number of results (default: 50)
    """
    return query_infrastructure_events.invoke({"hours": hours, "limit": limit})


@mcp.tool()
def search_logs_for_ip(ip_address: str, hours: int = 1, limit: int = 100) -> str:
    """Search logs for a specific IP address.

    Args:
        ip_address: IP address to search for
        hours: Lookback period in hours (default: 1)
        limit: Maximum number of log entries (default: 100)
    """
    return search_logs_by_ip.invoke({
        "ip_address": ip_address,
        "hours": hours,
        "limit": limit
    })


# === Main Entry Point ===

if __name__ == "__main__":
    print("Starting DNS Security MCP Server (FastMCP + HTTP)...", file=sys.stderr)
    print(f"Server will listen on http://0.0.0.0:8080", file=sys.stderr)
    print(file=sys.stderr)

    # Run FastMCP server
    mcp.run(host="0.0.0.0", port=8080)
