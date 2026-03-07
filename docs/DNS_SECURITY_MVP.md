# DNS Security MVP — Hierarchical AI Agent System

**Status:** ✅ **Complete and Deployed**

The DNS Security MVP provides AI-powered network security analysis through a hierarchical agent system that queries DNS metrics, logs, and security data from SigNoz/ClickHouse. The system exposes 10 specialized DNS security tools via Model Context Protocol (MCP), enabling Claude Desktop to query your network security data using natural language.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Claude Desktop                           │
│                   (MCP Client)                              │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP/SSE
                       │ localhost → docker.mcducklabs.com:8082
┌──────────────────────▼──────────────────────────────────────┐
│              MCP Server (fl-mcp container)                  │
│  ┌────────────────────────────────────────────────────┐    │
│  │         10 DNS Security Tools (MCP Protocol)       │    │
│  │  • top_dns_clients      • security_summary         │    │
│  │  • dns_block_rates      • dns_anomalies            │    │
│  │  • high_risk_clients    • wireless_health          │    │
│  │  • blocked_domains      • infrastructure_events    │    │
│  │  • dns_traffic_by_type  • search_logs_for_ip       │    │
│  └────────────────────────────────────────────────────┘    │
│                         │                                    │
│  ┌──────────────────────▼──────────────────────────────┐   │
│  │    Hierarchical Agent System (LangGraph)            │   │
│  │  ┌──────────────────────────────────────────────┐  │   │
│  │  │         DNS Supervisor Agent                  │  │   │
│  │  │  (Orchestrates 5 micro-agents)               │  │   │
│  │  └───────────────────┬──────────────────────────┘  │   │
│  │          ┌───────────┼───────────┬─────────┐       │   │
│  │          ▼           ▼           ▼         ▼       │   │
│  │  ┌───────────┐ ┌──────────┐ ┌────────┐ ┌──────┐  │   │
│  │  │Top Clients│ │Block Rate│ │High Risk│ │ ...  │  │   │
│  │  │  Agent    │ │  Agent   │ │  Agent  │ │      │  │   │
│  │  └───────────┘ └──────────┘ └────────┘ └──────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP (ClickHouse port 8123)
┌──────────────────────▼──────────────────────────────────────┐
│           SigNoz / ClickHouse (signoz-clickhouse)           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Metrics: signoz_metrics.samples_v4                 │   │
│  │  Logs: signoz_logs.logs (AdGuard, pfSense, etc.)    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Features

### 🛠️ 10 DNS Security Tools

**Metrics Tools** (VictoriaMetrics/PromQL):
1. **top_dns_clients** - Top DNS clients by query volume
2. **dns_block_rates** - Block rates per client
3. **high_risk_clients** - Clients with suspicious activity
4. **blocked_domains** - Most frequently blocked domains
5. **dns_traffic_by_type** - Query volume by response type

**Logs Tools** (Loki/LogQL):
6. **security_summary** - Security threats and blocks
7. **dns_anomalies** - Unusual DNS patterns
8. **wireless_health** - Wireless network health
9. **infrastructure_events** - Infrastructure alerts
10. **search_logs_for_ip** - IP-specific log search

### 🤖 Hierarchical Agent System

**DNS Supervisor Agent:**
- Orchestrates 5 specialized micro-agents
- Synthesizes findings across all data sources
- Provides actionable security recommendations

**5 Micro-Agents:**
- Top Clients Analyzer
- Block Rate Monitor
- High Risk Detector
- Blocked Domains Tracker
- Traffic Pattern Analyzer

**State Management:**
- Redis-backed state persistence
- Cross-session context maintenance
- Conversation history tracking

**Observability:**
- Full Langfuse integration
- Trace every agent decision
- Debug agent behavior in production

## Deployment

### Server Location
- **Host:** docker.mcducklabs.com (192.168.2.106)
- **Container:** fl-mcp
- **Port:** 8082 (external) → 8080 (internal)
- **Network:** signoz-net (Docker network)

### Configuration

**Environment Variables** (`/opt/first-light/.env`):
```bash
# SigNoz / ClickHouse
SIGNOZ_BASE_URL=http://signoz-query-service:8080
SIGNOZ_CLICKHOUSE_HOST=clickhouse
SIGNOZ_CLICKHOUSE_USER=default
SIGNOZ_CLICKHOUSE_PASSWORD=

# Telegram (optional for MCP server)
TELEGRAM_BOT_TOKEN=<token>
TELEGRAM_CHAT_ID=<chat-id>
```

### Docker Compose

The MCP server runs as a service in docker-compose:

```yaml
mcp-server:
  build:
    context: .
    dockerfile: mcp_servers/Dockerfile
  container_name: fl-mcp
  restart: unless-stopped
  environment:
    - SIGNOZ_BASE_URL=${SIGNOZ_BASE_URL}
    - SIGNOZ_CLICKHOUSE_HOST=${SIGNOZ_CLICKHOUSE_HOST}
    - SIGNOZ_CLICKHOUSE_USER=${SIGNOZ_CLICKHOUSE_USER}
    - SIGNOZ_CLICKHOUSE_PASSWORD=${SIGNOZ_CLICKHOUSE_PASSWORD}
  ports:
    - "8082:8080"
  networks:
    - signoz-net
  depends_on:
    - clickhouse
```

### Deployment Commands

```bash
# On remote (docker.mcducklabs.com)
cd /opt/first-light
git pull
docker compose up -d --build mcp-server

# Check status
docker compose ps mcp-server
docker compose logs -f mcp-server

# Health check
curl http://localhost:8082/health
```

## Usage via Claude Desktop

### Setup

1. **Configure Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "first-light-dns": {
      "command": "/Users/tbailey/.local/bin/mcp-proxy",
      "env": {
        "SSE_URL": "http://docker.mcducklabs.com:8082/sse"
      }
    }
  }
}
```

2. **Restart Claude Desktop completely** (Cmd+Q, then relaunch)

3. **Verify connection** - Look for the 🔌 icon indicating MCP tools are available

### Example Queries

**Network Security Analysis:**
- "What are the top DNS clients in the last 24 hours?"
- "Show me clients with high block rates"
- "Which domains are being blocked most frequently?"
- "Are there any high-risk clients with suspicious activity?"

**Threat Investigation:**
- "Search logs for IP 192.168.1.50 in the last hour"
- "Show me DNS anomalies and unusual patterns"
- "What's the security summary for the last 6 hours?"

**Infrastructure Monitoring:**
- "What's the wireless network health status?"
- "Show me recent infrastructure events"
- "Break down DNS traffic by query type"

**Ad-hoc Analysis:**
- "Compare block rates between 192.168.1.100 and 192.168.2.52"
- "What's changed in DNS traffic over the last week?"
- "Identify any new devices making DNS queries"

## Development

### Project Structure

```
first-light/
├── agent/
│   ├── config.py                 # Configuration (SigNoz, ClickHouse)
│   ├── state.py                  # State management (Redis)
│   ├── agent_factory.py          # Agent creation
│   ├── graphs/
│   │   └── dns_security_graph.py # DNS domain LangGraph
│   └── tools/
│       ├── metrics.py            # PromQL queries (5 tools)
│       └── logs.py               # LogQL queries (5 tools)
│
├── mcp_servers/
│   ├── dns_security.py           # MCP server (HTTP/SSE)
│   ├── Dockerfile                # Container build
│   └── README.md                 # MCP server docs
│
├── scripts/
│   ├── test_mcp_minimal.py       # Quick MCP test
│   └── test_mcp_list_tools.py    # List all tools
│
└── tests/
    └── integration/
        ├── test_dns_security.py  # Agent tests
        └── test_mcp_e2e.py       # MCP E2E tests
```

### Local Development

**Run MCP server locally:**
```bash
cd /Users/tbailey/Dev/first-light
python mcp_servers/dns_security.py
```

**Test with MCP client:**
```bash
python scripts/test_mcp_minimal.py --host localhost --port 8080
python scripts/test_mcp_list_tools.py
```

**Run integration tests:**
```bash
pytest tests/integration/test_dns_security.py -v
pytest tests/integration/test_mcp_e2e.py -v
```

### Key Technologies

- **MCP Protocol:** Model Context Protocol for LLM-tool integration
- **LangGraph:** State machine for multi-agent orchestration
- **LangChain:** Tool definitions and agent framework
- **Langfuse:** Observability and tracing
- **ClickHouse:** High-performance analytics database
- **SigNoz:** Observability platform (metrics + logs)
- **Starlette:** Async web framework for MCP server
- **httpx:** HTTP client for ClickHouse queries

### Tool Implementation Pattern

All tools follow this pattern:

```python
from langchain_core.tools import tool
from agent.config import get_config
import httpx

@tool
def query_example(hours: int = 24, limit: int = 20) -> str:
    """Tool description for LLM.

    Args:
        hours: Lookback period
        limit: Max results
    """
    config = get_config()

    # ClickHouse query
    query = """
        SELECT ...
        FROM signoz_metrics.samples_v4
        WHERE ...
        LIMIT {limit}
    """

    # Execute via HTTP
    clickhouse_url = f"http://{config.signoz_clickhouse_host}:8123"
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            clickhouse_url,
            params={
                "user": config.signoz_clickhouse_user,
                "password": config.signoz_clickhouse_password,
                "query": query
            }
        )

    return response.text.strip()
```

## Testing

### Manual Testing

**Test tool invocation:**
```bash
python scripts/test_mcp_minimal.py
```

Expected output:
```
✓ SSE connected
✓ Session created
✓ Initialized: protocolVersion='2025-11-25'
✓ Found 10 tools
✓ Tool call completed
Result: 192.168.1.100	192.168.1.100	1791029
        192.168.2.52	192.168.2.52	1084384
        192.168.1.65	192.168.1.65	3461

✓ All tests passed!
```

**List all tools:**
```bash
python scripts/test_mcp_list_tools.py
```

### Automated Testing

**Run full test suite:**
```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/test_dns_security.py -v

# MCP E2E tests (requires server running)
pytest tests/integration/test_mcp_e2e.py -v
```

## Troubleshooting

### MCP Server Issues

**Check container status:**
```bash
docker compose ps mcp-server
docker compose logs --tail=50 mcp-server
```

**Verify connectivity:**
```bash
curl http://docker.mcducklabs.com:8082/health
# Should return: OK
```

**Test tool execution:**
```bash
docker exec fl-mcp python -c "
from agent.tools.metrics import query_adguard_top_clients
print(query_adguard_top_clients.invoke({'hours': 1, 'limit': 3}))
"
```

### Claude Desktop Connection

**Verify MCP proxy is installed:**
```bash
which mcp-proxy
# Should show: /Users/tbailey/.local/bin/mcp-proxy
```

**Check Claude Desktop logs:**
```bash
tail -f ~/Library/Logs/Claude/mcp*.log
```

**Common issues:**
- Missing `mcp-proxy` → Install from MCP documentation
- Wrong URL → Must be `http://docker.mcducklabs.com:8082/sse`
- Server not running → Check `docker compose ps mcp-server`

### ClickHouse Connection

**Verify ClickHouse is reachable:**
```bash
docker exec fl-mcp curl -s "http://clickhouse:8123/?query=SELECT%201"
# Should return: 1
```

**Test query execution:**
```bash
docker exec fl-mcp python -c "
import httpx
response = httpx.post('http://clickhouse:8123', params={
    'user': 'default',
    'query': 'SELECT count() FROM signoz_metrics.samples_v4'
})
print(response.text)
"
```

## Performance

- **Query latency:** ~100-500ms per tool call
- **Connection pooling:** httpx client with 30s timeout
- **Rate limiting:** None (internal network)
- **Concurrent requests:** Handled by Starlette async framework

## Security

- **Network isolation:** MCP server runs in Docker network, not exposed to internet
- **Authentication:** No authentication required (localhost/internal only)
- **Authorization:** None (trusted network environment)
- **Data access:** Read-only queries to ClickHouse
- **Secrets:** Stored in .env file (gitignored)

## Monitoring

**Health check endpoint:**
```bash
curl http://docker.mcducklabs.com:8082/health
```

**Server metrics:**
- Check Langfuse for agent traces
- Monitor ClickHouse query performance
- Track tool invocation patterns in Claude Desktop

**Alerts:**
- Container down → Docker health check
- Query failures → Check ClickHouse logs
- High latency → Investigate query performance

## Roadmap

### ✅ Completed (MVP)
- Hierarchical agent system
- 10 DNS security tools
- MCP server with HTTP/SSE transport
- Claude Desktop integration
- Real-time query execution
- State management and tracing

### 🔜 Future Enhancements
- Statistical anomaly detection engine (#21)
- Threat intelligence enrichment (AbuseIPDB, VirusTotal) (#22)
- Device inventory database (#23)
- ntopng integration for flow data (#24)
- Uptime Kuma integration (#25)
- Automated security reports
- Historical trend analysis
- Proactive threat detection

## References

- [MCP Server README](../mcp_servers/README.md) - MCP server implementation details
- [Model Context Protocol](https://modelcontextprotocol.io) - Official MCP documentation
- [LangGraph](https://langchain-ai.github.io/langgraph/) - Multi-agent orchestration
- [SigNoz](https://signoz.io) - Observability platform
- [ClickHouse](https://clickhouse.com) - Analytics database

---

**MVP Status:** ✅ **Complete and Production-Ready**
**Deployed:** docker.mcducklabs.com:8082
**Last Updated:** March 7, 2026
