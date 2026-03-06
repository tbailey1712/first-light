#!/usr/bin/env python3
"""
DNS Security MCP Server

Exposes First Light DNS security tools via Model Context Protocol (MCP).
Allows any MCP-compatible client to query DNS metrics, logs, and analytics.

Usage:
    python mcp_servers/dns_security.py

Environment:
    Requires .env file with SigNoz credentials (same as main agent)
"""

import asyncio
import os
import sys
from typing import Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from agent.tools import get_all_tools


# === MCP Server Setup ===

# Create MCP server instance
app = Server("dns-security")

# Get all DNS tools from the agent
dns_tools = get_all_tools()


# === Tool Registration ===

@app.list_tools()
async def list_tools() -> list[Tool]:
    """
    List all available DNS security tools.

    Converts LangChain tools to MCP Tool format.
    """
    mcp_tools = []

    for langchain_tool in dns_tools:
        # Extract tool metadata from LangChain tool
        tool_name = langchain_tool.name
        description = langchain_tool.description or "No description"

        # Parse args schema from LangChain tool
        args_schema = {}
        if hasattr(langchain_tool, 'args_schema') and langchain_tool.args_schema:
            schema = langchain_tool.args_schema
            if hasattr(schema, 'model_json_schema'):
                schema_dict = schema.model_json_schema()
                args_schema = {
                    "type": "object",
                    "properties": schema_dict.get("properties", {}),
                    "required": schema_dict.get("required", [])
                }

        # Create MCP Tool
        mcp_tool = Tool(
            name=tool_name,
            description=description,
            inputSchema=args_schema if args_schema else {"type": "object"}
        )

        mcp_tools.append(mcp_tool)

    return mcp_tools


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """
    Execute a DNS security tool.

    Args:
        name: Tool name
        arguments: Tool arguments

    Returns:
        List of TextContent with tool results
    """
    # Find the matching LangChain tool
    langchain_tool = None
    for tool in dns_tools:
        if tool.name == name:
            langchain_tool = tool
            break

    if not langchain_tool:
        return [TextContent(
            type="text",
            text=f"Error: Tool '{name}' not found. Available tools: {[t.name for t in dns_tools]}"
        )]

    try:
        # Execute the tool
        # LangChain tools can be called with invoke() or as a function
        if hasattr(langchain_tool, 'invoke'):
            result = langchain_tool.invoke(arguments)
        else:
            # Fallback: call as function
            result = langchain_tool.run(**arguments)

        # Return result as TextContent
        return [TextContent(
            type="text",
            text=str(result)
        )]

    except Exception as e:
        # Return error message
        return [TextContent(
            type="text",
            text=f"Error executing tool '{name}': {str(e)}"
        )]


# === Main Entry Point ===

async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    print("Starting DNS Security MCP Server...", file=sys.stderr)
    print(f"Loaded {len(dns_tools)} tools:", file=sys.stderr)
    for tool in dns_tools:
        print(f"  - {tool.name}", file=sys.stderr)
    print(file=sys.stderr)

    asyncio.run(main())
