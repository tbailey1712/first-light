#!/usr/bin/env python3
"""Minimal MCP client test to debug connection issues."""

import asyncio
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

async def main():
    url = "http://docker.mcducklabs.com:8082/mcp/sse"
    print(f"Connecting to {url}...")

    try:
        async with sse_client(url) as (read, write):
            print("✓ SSE connected")

            async with ClientSession(read, write) as session:
                print("✓ Session created")

                init_result = await session.initialize()
                print(f"✓ Initialized: {init_result}")

                tools_result = await session.list_tools()
                print(f"✓ Found {len(tools_result.tools)} tools")

                # Try calling one tool
                result = await session.call_tool("top_dns_clients", {"hours": 1, "limit": 3})
                print(f"✓ Tool call completed")
                print(f"Result: {result.content[0].text[:100] if result.content else 'No content'}")

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    print("\n✓ All tests passed!")
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
