#!/usr/bin/env python3
"""List all available MCP tools."""

import asyncio
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

async def main():
    url = "http://docker.mcducklabs.com:8082/sse"

    try:
        async with sse_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools_result = await session.list_tools()

                print(f"\n{'='*80}")
                print(f"MCP SERVER TOOLS - {len(tools_result.tools)} available")
                print(f"{'='*80}\n")

                for i, tool in enumerate(tools_result.tools, 1):
                    print(f"{i}. {tool.name}")
                    print(f"   Description: {tool.description}")

                    # Show parameters
                    if tool.inputSchema and 'properties' in tool.inputSchema:
                        props = tool.inputSchema['properties']
                        if props:
                            print(f"   Parameters:")
                            for param_name, param_info in props.items():
                                param_type = param_info.get('type', 'any')
                                param_desc = param_info.get('description', '')
                                default = param_info.get('default', '')
                                default_str = f" (default: {default})" if default else ""
                                print(f"     - {param_name} ({param_type}){default_str}: {param_desc}")

                    # Show required fields
                    if tool.inputSchema and 'required' in tool.inputSchema:
                        required = tool.inputSchema['required']
                        if required:
                            print(f"   Required: {', '.join(required)}")

                    print()

                print(f"{'='*80}")
                print(f"All tools successfully registered and accessible via MCP protocol")
                print(f"{'='*80}\n")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
