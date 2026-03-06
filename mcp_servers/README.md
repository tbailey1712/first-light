# First Light MCP Server

Model Context Protocol (MCP) server that exposes First Light's DNS security tools over HTTP using [FastMCP](https://github.com/jlowin/fastmcp).

## What is MCP?

[Model Context Protocol](https://modelcontextprotocol.io) is a standard protocol for connecting AI models to external tools and data sources. This MCP server allows:

- Claude Desktop to query your network's DNS security data
- Other MCP-compatible AI applications to access DNS analytics
- Custom clients to integrate with your observability stack

## Architecture

```
┌─────────────────────┐
│   Claude Desktop    │
│   (MCP Client)      │
└──────────┬──────────┘
           │ HTTP + SSE
           │ localhost:8080
┌──────────▼──────────┐
│  fl-mcp container   │
│  (FastMCP server)   │
└──────────┬──────────┘
           │ Docker network
┌──────────▼──────────┐
│  SigNoz/ClickHouse  │
│  (Metrics + Logs)   │
└─────────────────────┘
```

**Key Benefits:**
- ✅ Runs in docker-compose with rest of stack
- ✅ Isolated with proper environment variables
- ✅ HTTP + SSE transport (no stdio complexity)
- ✅ Auto-discovery in Claude Desktop
- ✅ Standard FastAPI/OpenAPI docs at http://localhost:8080/docs

## Available Tools

### Metrics Tools (VictoriaMetrics/PromQL)
- `top_dns_clients` - Top DNS clients by query volume
- `dns_block_rates` - Block rates per client
- `high_risk_clients` - Clients with suspicious activity
- `blocked_domains` - Most frequently blocked domains
- `dns_traffic_by_type` - Query volume by response type

### Logs Tools (Loki/LogQL)
- `security_summary` - Security threats and blocks
- `dns_anomalies` - Unusual DNS patterns
- `wireless_health` - Wireless network health
- `infrastructure_events` - Infrastructure alerts
- `search_logs_for_ip` - IP-specific log search

## Quick Start

### 1. Start the MCP Server

```bash
docker-compose up -d mcp-server
```

Check status:
```bash
docker-compose ps mcp-server
docker-compose logs -f mcp-server
```

Verify it's running:
```bash
curl http://localhost:8080/health
```

### 2. Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "first-light-dns": {
      "url": "http://localhost:8080/mcp",
      "transport": "sse"
    }
  }
}
```

### 3. Restart Claude Desktop

Quit Claude Desktop completely and restart it. The MCP server will be auto-discovered.

### 4. Test It

Ask Claude:
- "What are the top DNS clients in the last 24 hours?"
- "Show me high-risk DNS clients"
- "What domains are being blocked most frequently?"
- "Search logs for IP 192.168.1.50"

Claude will automatically use the MCP tools to query your network data!

## Usage Examples

### Via Claude Desktop

Just ask natural language questions:

```
You: "What are the top DNS clients?"

Claude: [calls top_dns_clients tool]
Here are the top DNS clients by query volume:

| Client              | IP           | Queries |
|---------------------|--------------|---------|
| laptop.local        | 192.168.1.50 | 15,432  |
| phone.local         | 192.168.1.75 | 8,921   |
...
```

### Via API (Direct HTTP)

You can also call the tools directly via HTTP:

```bash
# List available tools
curl http://localhost:8080/mcp/tools

# Call a tool
curl -X POST http://localhost:8080/mcp/tools/top_dns_clients \
  -H "Content-Type: application/json" \
  -d '{"hours": 24, "limit": 10}'
```

### Via FastAPI Docs

Open http://localhost:8080/docs in your browser for interactive API documentation.

## Configuration

### Environment Variables

Set in docker-compose.yml (already configured):

```yaml
environment:
  - SIGNOZ_BASE_URL=${SIGNOZ_BASE_URL}
  - SIGNOZ_CLICKHOUSE_HOST=${SIGNOZ_CLICKHOUSE_HOST}
  - SIGNOZ_CLICKHOUSE_USER=${SIGNOZ_CLICKHOUSE_USER}
  - SIGNOZ_CLICKHOUSE_PASSWORD=${SIGNOZ_CLICKHOUSE_PASSWORD}
```

These are loaded from your `.env` file.

### Port Configuration

Default: `8080`

To change:
1. Edit `docker-compose.yml` - change port mapping
2. Update Claude Desktop config with new URL

## Development

### Local Testing (Without Container)

```bash
# Install dependencies
pip install -r requirements.txt

# Run MCP server locally
python mcp_servers/dns_security.py
```

Access at http://localhost:8080

### Adding New Tools

1. Add tool function to `agent/tools/metrics.py` or `agent/tools/logs.py`
2. Import it in `mcp_servers/dns_security.py`
3. Register it with `@mcp.tool()` decorator
4. Rebuild container: `docker-compose up -d --build mcp-server`

Example:

```python
@mcp.tool()
def my_new_tool(param: str, hours: int = 24) -> str:
    """Description of what this tool does.

    Args:
        param: Description of parameter
        hours: Lookback period in hours
    """
    # Your implementation
    return result
```

### Testing

```bash
# Run MCP server tests
pytest tests/integration/test_mcp_server.py -v

# Test specific tool
curl -X POST http://localhost:8080/mcp/tools/top_dns_clients \
  -H "Content-Type: application/json" \
  -d '{"hours": 1, "limit": 5}'
```

## Troubleshooting

### Server won't start

```bash
# Check container logs
docker-compose logs mcp-server

# Check if port 8080 is already in use
lsof -i :8080

# Verify ClickHouse connection
docker-compose exec mcp-server python -c "
from agent.config import get_config
config = get_config()
print(f'ClickHouse host: {config.signoz_clickhouse_host}')
"
```

### Claude Desktop can't connect

1. **Verify server is running:**
   ```bash
   curl http://localhost:8080/health
   ```

2. **Check Claude Desktop config path:**
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Must be valid JSON
   - URL must be `http://localhost:8080/mcp`
   - Transport must be `sse`

3. **Restart Claude Desktop completely:**
   - Quit (Cmd+Q)
   - Restart from Applications folder
   - Check server logs for connection attempts

### Tools return errors

1. **Verify SigNoz/ClickHouse is running:**
   ```bash
   docker-compose ps clickhouse
   ```

2. **Check credentials:**
   ```bash
   docker-compose exec mcp-server env | grep SIGNOZ
   ```

3. **Test query directly:**
   ```bash
   docker-compose exec mcp-server python -c "
   from agent.tools.metrics import query_adguard_top_clients
   print(query_adguard_top_clients.invoke({'hours': 1, 'limit': 5}))
   "
   ```

### Port conflicts

If port 8080 is already in use:

1. Edit `docker-compose.yml`:
   ```yaml
   ports:
     - "8081:8080"  # Use 8081 on host
   ```

2. Update Claude Desktop config:
   ```json
   {
     "mcpServers": {
       "first-light-dns": {
         "url": "http://localhost:8081/mcp",
         "transport": "sse"
       }
     }
   }
   ```

3. Restart: `docker-compose up -d mcp-server`

## Security Notes

- MCP server runs in isolated container
- Only accessible on localhost (not exposed to network)
- Uses read-only database credentials
- All tools are read-only (no write operations)
- Same security boundary as SigNoz stack

## Performance

- Tools use efficient PromQL/LogQL queries
- Default time ranges limited to prevent long queries
- Results cached by Claude Desktop per conversation
- Container uses minimal resources (~100MB RAM)

## Next Steps

- **Try it:** Start the server and ask Claude about your DNS data
- **Extend it:** Add tools for other data sources (ntopng, Uptime Kuma, validator metrics)
- **Automate it:** Use MCP tools in Claude Projects for automated network analysis
- **Integrate it:** Build custom MCP clients for dashboards or alerting

## References

- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io)
- [Claude Desktop MCP Guide](https://modelcontextprotocol.io/quickstart/user)
- [First Light Project Documentation](../README.md)
