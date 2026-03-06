#!/bin/bash
# Run DNS Security MCP Server
# Usage: ./scripts/run_mcp_server.sh

set -e

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

cd "$PROJECT_ROOT"

# Load environment
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Run MCP server
echo "Starting DNS Security MCP Server..." >&2
echo "Project root: $PROJECT_ROOT" >&2
echo "" >&2

exec python mcp_servers/dns_security.py
