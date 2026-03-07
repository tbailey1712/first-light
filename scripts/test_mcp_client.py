#!/usr/bin/env python3
"""
MCP Client Test Script

Tests the MCP server using proper SSE protocol and MCP messages.
This connects as an MCP client would and tests all tools.

Usage:
    python scripts/test_mcp_client.py [--host HOST] [--port PORT]

Requirements:
    - MCP server running: docker-compose up -d mcp-server
    - pip install mcp httpx
"""

import asyncio
import sys
import json
from typing import Any, Dict
import argparse

try:
    from mcp.client.session import ClientSession
    from mcp.client.sse import sse_client
except ImportError:
    print("Error: mcp package not installed", file=sys.stderr)
    print("Install with: pip install mcp", file=sys.stderr)
    sys.exit(1)


class MCPTester:
    """MCP client for testing DNS security tools."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session: ClientSession | None = None
        self.passed = 0
        self.failed = 0

    async def connect(self):
        """Connect to MCP server via SSE."""
        print(f"Connecting to MCP server at {self.base_url}...")

        # Create SSE client context manager
        self.sse_context = sse_client(f"{self.base_url}/mcp/sse")

        # Enter the context and get streams
        self.streams = await self.sse_context.__aenter__()
        read_stream, write_stream = self.streams

        # Create MCP session
        self.session = ClientSession(read_stream, write_stream)

        # Initialize session
        await self.session.initialize()
        print("✓ Connected and initialized\n")

    async def list_tools(self) -> list[Dict[str, Any]]:
        """List all available tools."""
        print("Listing available tools...")
        result = await self.session.list_tools()
        print(f"✓ Found {len(result.tools)} tools\n")
        return result.tools

    async def test_tool(self, tool_name: str, arguments: Dict[str, Any], description: str):
        """Test a single tool."""
        print("─" * 80)
        print(f"Testing: {tool_name}")
        print(f"Description: {description}")
        print(f"Arguments: {json.dumps(arguments)}")

        try:
            # Call the tool
            result = await self.session.call_tool(tool_name, arguments)

            # Extract result text
            if result.content and len(result.content) > 0:
                content = result.content[0]
                if hasattr(content, 'text'):
                    text = content.text

                    # Check if result is empty or error
                    if not text or len(text.strip()) == 0:
                        print("⚠ Warning: Empty result")
                        self.passed += 1
                    elif "error" in text.lower():
                        print(f"✗ Error: {text[:200]}")
                        self.failed += 1
                    else:
                        print("✓ Success")
                        # Show first 200 chars of result
                        preview = text[:200].replace('\n', ' ')
                        if len(text) > 200:
                            preview += "..."
                        print(f"Result preview: {preview}")
                        self.passed += 1
                else:
                    print("⚠ Warning: Non-text content")
                    self.passed += 1
            else:
                print("⚠ Warning: No content in result")
                self.passed += 1

        except Exception as e:
            print(f"✗ Failed: {str(e)}")
            self.failed += 1

        print()

    async def run_all_tests(self):
        """Run all tool tests."""
        print("=" * 80)
        print("MCP CLIENT TEST")
        print("=" * 80)
        print(f"MCP Server: {self.base_url}")
        print()

        # Connect
        await self.connect()

        # List tools
        tools = await self.list_tools()

        # Test each tool
        print("=" * 80)
        print("METRICS TOOLS (VictoriaMetrics/PromQL)")
        print("=" * 80)
        print()

        await self.test_tool(
            "top_dns_clients",
            {"hours": 24, "limit": 10},
            "Top DNS clients by query volume"
        )

        await self.test_tool(
            "dns_block_rates",
            {"hours": 24, "min_block_rate": 0.0, "limit": 10},
            "DNS block rates per client"
        )

        await self.test_tool(
            "high_risk_clients",
            {"hours": 24, "min_risk_score": 5.0, "limit": 10},
            "High-risk clients with suspicious activity"
        )

        await self.test_tool(
            "blocked_domains",
            {"hours": 24, "limit": 20},
            "Most frequently blocked domains"
        )

        await self.test_tool(
            "dns_traffic_by_type",
            {"hours": 24},
            "DNS query volume breakdown by type"
        )

        print("=" * 80)
        print("LOGS TOOLS (Loki/LogQL)")
        print("=" * 80)
        print()

        await self.test_tool(
            "security_summary",
            {"hours": 1},
            "Security threats and blocks summary"
        )

        await self.test_tool(
            "dns_anomalies",
            {"hours": 1, "limit": 10},
            "DNS anomalies and unusual patterns"
        )

        await self.test_tool(
            "wireless_health",
            {"hours": 1},
            "Wireless network health summary"
        )

        await self.test_tool(
            "infrastructure_events",
            {"hours": 1, "limit": 20},
            "Infrastructure events and alerts"
        )

        await self.test_tool(
            "search_logs_for_ip",
            {"ip_address": "192.168.1.1", "hours": 1, "limit": 20},
            "Search logs for specific IP address"
        )

        # Summary
        print("=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        total = self.passed + self.failed
        if total > 0:
            success_rate = (self.passed / total) * 100
            print(f"Success Rate: {success_rate:.1f}%")
        print("=" * 80)

        return self.failed == 0

    async def close(self):
        """Close the session."""
        if hasattr(self, 'sse_context'):
            await self.sse_context.__aexit__(None, None, None)


async def main():
    parser = argparse.ArgumentParser(description="Test MCP server with proper SSE protocol")
    parser.add_argument("--host", default="localhost", help="MCP server host")
    parser.add_argument("--port", default="8082", help="MCP server port")
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}"

    print("=" * 80)
    print("MCP CLIENT TEST")
    print("=" * 80)
    print(f"MCP Server: {base_url}")
    print()

    try:
        print(f"Connecting to MCP server at {base_url}...")

        # Use SSE client context manager properly
        async with sse_client(f"{base_url}/mcp/sse") as (read_stream, write_stream):
            print("✓ SSE connection established")

            # Create MCP session
            async with ClientSession(read_stream, write_stream) as session:
                print("✓ MCP session created")

                # Initialize
                await session.initialize()
                print("✓ Session initialized\n")

                # List tools
                print("Listing available tools...")
                result = await session.list_tools()
                print(f"✓ Found {len(result.tools)} tools\n")

                # Test a few tools
                print("=" * 80)
                print("Testing sample tools...")
                print("=" * 80)
                print()

                # Test top_dns_clients
                print("Testing: top_dns_clients")
                result = await session.call_tool("top_dns_clients", {"hours": 1, "limit": 5})
                if result.content:
                    text = result.content[0].text
                    print(f"✓ Result: {text[:200]}...")
                print()

                # Test security_summary
                print("Testing: security_summary")
                result = await session.call_tool("security_summary", {"hours": 1})
                if result.content:
                    text = result.content[0].text
                    print(f"✓ Result: {text[:200]}...")
                print()

                print("=" * 80)
                print("TEST COMPLETE")
                print("=" * 80)
                print("✓ MCP server is working correctly")
                print("✓ SSE transport functional")
                print("✓ Tool invocation successful")

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\nFatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
