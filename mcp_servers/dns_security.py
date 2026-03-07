#!/usr/bin/env python3
"""
DNS Security MCP Server (HTTP/SSE)

Exposes First Light DNS security tools via Model Context Protocol over HTTP.
Runs as a containerized service in docker-compose, accessible on port 8080.

Usage:
    python mcp_servers/dns_security.py

Environment:
    Requires SigNoz credentials in .env or environment variables
"""

import os
import sys
import asyncio
from typing import Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.responses import Response
import uvicorn

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


# Create MCP server
app = Server("dns-security")


# === Tool Registration ===

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List all available DNS security tools."""
    return [
        Tool(
            name="top_dns_clients",
            description="Get top DNS clients by query volume",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 24},
                    "limit": {"type": "integer", "description": "Number of results", "default": 20}
                }
            }
        ),
        Tool(
            name="dns_block_rates",
            description="Get DNS block rates per client",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 24},
                    "min_block_rate": {"type": "number", "description": "Minimum block rate threshold", "default": 0.0},
                    "limit": {"type": "integer", "description": "Number of results", "default": 20}
                }
            }
        ),
        Tool(
            name="high_risk_clients",
            description="Get high-risk DNS clients with suspicious activity",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 24},
                    "min_risk_score": {"type": "number", "description": "Minimum risk score threshold", "default": 5.0},
                    "limit": {"type": "integer", "description": "Number of results", "default": 20}
                }
            }
        ),
        Tool(
            name="blocked_domains",
            description="Get most frequently blocked domains",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 24},
                    "limit": {"type": "integer", "description": "Number of results", "default": 50}
                }
            }
        ),
        Tool(
            name="dns_traffic_by_type",
            description="Get DNS query volume breakdown by response type",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 24}
                }
            }
        ),
        Tool(
            name="security_summary",
            description="Get security summary showing threats, blocks, and attacks",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 1}
                }
            }
        ),
        Tool(
            name="dns_anomalies",
            description="Get DNS anomalies and unusual patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 1},
                    "limit": {"type": "integer", "description": "Number of results", "default": 20}
                }
            }
        ),
        Tool(
            name="wireless_health",
            description="Get wireless network health summary",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 1}
                }
            }
        ),
        Tool(
            name="infrastructure_events",
            description="Get infrastructure events and alerts",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 1},
                    "limit": {"type": "integer", "description": "Number of results", "default": 50}
                }
            }
        ),
        Tool(
            name="search_logs_for_ip",
            description="Search logs for a specific IP address",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "IP address to search for"},
                    "hours": {"type": "integer", "description": "Lookback period in hours", "default": 1},
                    "limit": {"type": "integer", "description": "Maximum number of log entries", "default": 100}
                },
                "required": ["ip_address"]
            }
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a DNS security tool."""
    tool_map = {
        "top_dns_clients": query_adguard_top_clients,
        "dns_block_rates": query_adguard_block_rates,
        "high_risk_clients": query_adguard_high_risk_clients,
        "blocked_domains": query_adguard_blocked_domains,
        "dns_traffic_by_type": query_adguard_traffic_by_type,
        "security_summary": query_security_summary,
        "dns_anomalies": query_adguard_anomalies,
        "wireless_health": query_wireless_health,
        "infrastructure_events": query_infrastructure_events,
        "search_logs_for_ip": search_logs_by_ip,
    }

    if name not in tool_map:
        return [TextContent(
            type="text",
            text=f"Error: Tool '{name}' not found"
        )]

    try:
        langchain_tool = tool_map[name]
        result = langchain_tool.invoke(arguments)

        return [TextContent(
            type="text",
            text=str(result)
        )]

    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error executing tool '{name}': {str(e)}"
        )]


# === HTTP Server Setup ===

sse_transport = SseServerTransport("/messages")


async def handle_sse(scope, receive, send):
    """Handle SSE connections for MCP."""
    async with sse_transport.connect_sse(scope, receive, send) as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


async def health_check(scope, receive, send):
    """Health check endpoint."""
    response = Response("OK", status_code=200)
    await response(scope, receive, send)


# Create Starlette app
from starlette.routing import Route

starlette_app = Starlette(
    routes=[
        Route("/mcp/sse", handle_sse),
        Route("/health", health_check),
    ]
)


if __name__ == "__main__":
    print("Starting DNS Security MCP Server (HTTP/SSE)...", file=sys.stderr)
    print(f"Server will listen on http://0.0.0.0:8080", file=sys.stderr)
    print(file=sys.stderr)

    # Run server
    uvicorn.run(
        starlette_app,
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )
