# First Light MCP Servers

Model Context Protocol (MCP) servers that expose First Light's network observability tools to any MCP-compatible client.

## What is MCP?

[Model Context Protocol](https://modelcontextprotocol.io) is a standard protocol for connecting AI models to external tools and data sources. MCP servers expose capabilities that can be used by:

- Claude Desktop
- Other MCP-compatible AI applications
- Custom MCP clients

## Available Servers

### DNS Security Server (`dns_security.py`)

Exposes DNS security and analytics tools for querying AdGuard metrics and logs.

**Available Tools:**

**Metrics (VictoriaMetrics/PromQL):**
- `query_adguard_top_clients` - Top DNS clients by query volume
- `query_adguard_block_rates` - DNS block rates per client
- `query_adguard_high_risk_clients` - Clients with suspicious activity
- `query_adguard_blocked_domains` - Most blocked domains
- `query_adguard_traffic_by_type` - Query volume by response type

**Logs (Loki/LogQL):**
- `query_security_summary` - Security threats and blocks summary
- `query_adguard_anomalies` - DNS anomalies and unusual patterns
- `query_wireless_health` - Wireless network health
- `query_infrastructure_events` - Infrastructure alerts
- `search_logs_by_ip` - Search logs for specific IP address

## Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment:**

   Create `.env` file with SigNoz credentials:
   ```bash
   SIGNOZ_BASE_URL=https://your-signoz-instance.com
   SIGNOZ_CLICKHOUSE_HOST=your-clickhouse-host
   SIGNOZ_CLICKHOUSE_USER=your-username
   SIGNOZ_CLICKHOUSE_PASSWORD=your-password
   ```

## Usage

### Running Standalone

```bash
python mcp_servers/dns_security.py
```

The server runs in stdio mode and communicates via stdin/stdout following the MCP protocol.

### Integrating with Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "first-light-dns": {
      "command": "python",
      "args": [
        "/path/to/first-light/mcp_servers/dns_security.py"
      ],
      "env": {
        "SIGNOZ_BASE_URL": "https://your-signoz-instance.com",
        "SIGNOZ_CLICKHOUSE_HOST": "your-clickhouse-host",
        "SIGNOZ_CLICKHOUSE_USER": "your-username",
        "SIGNOZ_CLICKHOUSE_PASSWORD": "your-password"
      }
    }
  }
}
```

Or reference your `.env` file:

```json
{
  "mcpServers": {
    "first-light-dns": {
      "command": "python",
      "args": [
        "/path/to/first-light/mcp_servers/dns_security.py"
      ],
      "envFile": "/path/to/first-light/.env"
    }
  }
}
```

### Using with Other MCP Clients

Any MCP-compatible client can connect to the server. The server follows the standard MCP protocol for:

- `tools/list` - List available tools
- `tools/call` - Execute a tool with arguments

Example tool call:

```json
{
  "method": "tools/call",
  "params": {
    "name": "query_adguard_top_clients",
    "arguments": {
      "hours": 24,
      "limit": 10
    }
  }
}
```

## Tool Examples

### Get Top DNS Clients

```python
# Via MCP client
result = await client.call_tool(
    "query_adguard_top_clients",
    {"hours": 24, "limit": 20}
)
```

Returns formatted table:
```
| Client              | IP           | Queries |
|---------------------|--------------|---------|
| laptop.local        | 192.168.1.50 | 15,432  |
| phone.local         | 192.168.1.75 | 8,921   |
| ...                 | ...          | ...     |
```

### Check High-Risk Clients

```python
result = await client.call_tool(
    "query_adguard_high_risk_clients",
    {"hours": 24, "min_risk_score": 7.0}
)
```

Returns JSON with risk analysis:
```json
{
  "high_risk_clients": [
    {
      "client": "unknown-device.local",
      "ip": "192.168.1.99",
      "risk_score": 8.5,
      "reasons": ["High block rate (45%)", "Unusual query patterns", "New device"]
    }
  ]
}
```

### Search Logs for IP

```python
result = await client.call_tool(
    "search_logs_by_ip",
    {"ip_address": "192.168.1.50", "hours": 1, "limit": 50}
)
```

Returns JSON with log entries:
```json
{
  "total_entries": 42,
  "entries": [
    {
      "timestamp": "2026-03-06T20:15:23Z",
      "service": "adguard",
      "message": "Query: example.com -> ALLOWED",
      "details": {...}
    },
    ...
  ]
}
```

## Architecture

```
┌─────────────────────┐
│   MCP Client        │
│ (Claude Desktop,    │
│  custom app, etc)   │
└──────────┬──────────┘
           │ MCP Protocol (stdio)
           │
┌──────────▼──────────┐
│  dns_security.py    │
│  (MCP Server)       │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  agent/tools/       │
│  - metrics.py       │
│  - logs.py          │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  SigNoz/ClickHouse  │
│  (Metrics + Logs)   │
└─────────────────────┘
```

## Development

### Adding New Tools

1. Add tool to `agent/tools/metrics.py` or `agent/tools/logs.py`
2. Register tool in `agent/tools/__init__.py` → `get_all_tools()`
3. Restart MCP server - new tool automatically exposed

### Testing

Test the MCP server with the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector python mcp_servers/dns_security.py
```

Or use the First Light test suite:

```bash
pytest tests/integration/test_mcp_server.py
```

## Troubleshooting

### Server won't start

- Check that `.env` file exists and has valid credentials
- Verify Python dependencies installed: `pip install -r requirements.txt`
- Check Python path includes project root

### Tools return errors

- Verify SigNoz/ClickHouse connection: `tests/test_connections.py`
- Check that metrics/logs exist for the requested time range
- Review server logs (stderr output)

### Claude Desktop can't find tools

- Check Claude Desktop config path
- Verify Python interpreter path in config
- Check `.env` file path if using `envFile`
- Restart Claude Desktop after config changes

## Security Notes

- MCP servers run with your local credentials
- Credentials passed via environment variables (never hardcoded)
- Server only exposes read-only query tools (no write operations)
- Runs locally - no network exposure unless you explicitly proxy it

## Next Steps

- **Try it:** Add to Claude Desktop and ask "What are the top DNS clients?"
- **Extend it:** Add more tools for different data sources (ntopng, Uptime Kuma, etc.)
- **Integrate it:** Use the MCP server from custom applications
- **Monitor it:** Tools support time range filtering for efficient queries

## References

- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [Claude Desktop MCP Guide](https://modelcontextprotocol.io/quickstart/user)
