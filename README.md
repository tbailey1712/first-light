# First Light — AI-Powered Network Security Platform

**Production-Ready Network Observability with Hierarchical AI Agents**

First Light is an AI-powered network security platform that provides real-time threat analysis, DNS security monitoring, and infrastructure observability through a unified interface. The system uses hierarchical AI agents to analyze network data and exposes security tools via Model Context Protocol (MCP) for natural language interaction through Claude Desktop.

## 🎯 Current Status

**✅ DNS Security MVP - COMPLETE**

- 10 DNS security tools exposed via MCP
- Hierarchical agent system with supervisor + 5 micro-agents
- Integrated with Claude Desktop for natural language queries
- Real-time analysis of network traffic, threats, and anomalies
- Production deployment on docker.mcducklabs.com

[→ DNS Security MVP Documentation](docs/DNS_SECURITY_MVP.md)

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Claude Desktop                           │
│                    (Natural Language UI)                     │
└────────────────────────┬─────────────────────────────────────┘
                         │ MCP Protocol (HTTP/SSE)
┌────────────────────────▼─────────────────────────────────────┐
│                  MCP Server (Port 8082)                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │          10 DNS Security Tools                         │ │
│  │  Metrics: top_clients, block_rates, high_risk, etc.   │ │
│  │  Logs: security_summary, anomalies, wireless_health   │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │     Hierarchical Agent System (LangGraph)              │ │
│  │  Supervisor + 5 Specialized Micro-Agents              │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬─────────────────────────────────────┘
                         │ ClickHouse HTTP API
┌────────────────────────▼─────────────────────────────────────┐
│                 SigNoz / ClickHouse                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Metrics (VictoriaMetrics) + Logs (Loki)              │ │
│  │  AdGuard DNS, pfSense, UniFi, Infrastructure           │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬─────────────────────────────────────┘
                         │ Syslog (UDP 514)
┌────────────────────────▼─────────────────────────────────────┐
│              Network Infrastructure                          │
│  pfSense • AdGuard • UniFi • QNAP • Proxmox • Validators   │
└──────────────────────────────────────────────────────────────┘
```

## ✨ Features

### 🤖 AI-Powered Analysis
- **Hierarchical Agents:** Supervisor coordinates 5 specialized micro-agents
- **Natural Language Interface:** Query network security via Claude Desktop
- **Real-time Analysis:** Live threat detection and anomaly identification
- **Contextual Understanding:** Agents maintain conversation state and history

### 🛡️ DNS Security Tools
1. **Top DNS Clients** - Identify highest volume clients
2. **Block Rate Analysis** - Monitor DNS blocking effectiveness
3. **High Risk Detection** - Flag suspicious client behavior
4. **Blocked Domains** - Track frequently blocked domains
5. **Traffic Patterns** - Analyze query types and trends
6. **Security Summary** - Aggregate threat intelligence
7. **Anomaly Detection** - Identify unusual DNS patterns
8. **Wireless Health** - Monitor WiFi network status
9. **Infrastructure Events** - Track system alerts
10. **IP Search** - Investigate specific addresses

### 📊 Observability Platform
- **Unified Logs:** SigNoz/Loki for all network logs
- **Metrics:** VictoriaMetrics for time-series data
- **Dashboards:** Pre-built Grafana dashboards
- **Tracing:** Langfuse integration for agent observability
- **Alerting:** CrowdSec for threat detection

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Network devices configured to send syslog
- Claude Desktop (for natural language interface)

### Deployment

1. **Clone repository:**
```bash
git clone <repo-url>
cd first-light
```

2. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your credentials
```

3. **Start the stack:**
```bash
docker compose up -d
```

4. **Verify services:**
```bash
docker compose ps
curl http://localhost:8082/health  # MCP server
```

5. **Configure Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "first-light-dns": {
      "command": "/path/to/mcp-proxy",
      "env": {
        "SSE_URL": "http://docker.mcducklabs.com:8082/sse"
      }
    }
  }
}
```

6. **Restart Claude Desktop** and start querying!

[→ Full DNS Security MVP Documentation](docs/DNS_SECURITY_MVP.md)

## 💬 Example Queries

Ask Claude Desktop:
- "What are the top DNS clients in the last 24 hours?"
- "Show me clients with high block rates"
- "Are there any high-risk clients with suspicious activity?"
- "What domains are being blocked most frequently?"
- "Search logs for IP 192.168.1.50"
- "What's the security summary for the last 6 hours?"
- "Show me DNS anomalies and unusual patterns"

## 🗂️ Project Structure

```
first-light/
├── agent/                      # AI agent system
│   ├── graphs/                 # LangGraph definitions
│   │   └── dns_security_graph.py
│   ├── tools/                  # Security tools
│   │   ├── metrics.py          # PromQL queries
│   │   └── logs.py             # LogQL queries
│   ├── config.py               # Configuration
│   ├── state.py                # State management
│   └── agent_factory.py        # Agent creation
│
├── mcp_servers/                # MCP server
│   ├── dns_security.py         # HTTP/SSE server
│   ├── Dockerfile              # Container build
│   └── README.md               # MCP documentation
│
├── signoz/                     # Observability stack
│   ├── docker-compose.yaml     # SigNoz services
│   ├── otel-collector-config.yaml
│   └── common/                 # Configs & dashboards
│
├── scripts/                    # Utilities
│   ├── test_mcp_minimal.py     # Quick MCP test
│   └── test_mcp_list_tools.py  # List all tools
│
├── tests/                      # Test suite
│   ├── unit/                   # Unit tests
│   └── integration/            # Integration tests
│
└── docs/                       # Documentation
    ├── DNS_SECURITY_MVP.md     # DNS Security guide
    └── ...                     # Other guides
```

## 📚 Documentation

- **[DNS Security MVP](docs/DNS_SECURITY_MVP.md)** - Complete DNS Security guide
- **[MCP Server](mcp_servers/README.md)** - MCP server implementation
- **[Configuration Guide](CONFIGURATION_GUIDE.md)** - Network device setup
- **[Deployment Guide](DEPLOY.md)** - Production deployment

## 🔧 Configuration

### Environment Variables

Key variables in `.env`:

```bash
# SigNoz / ClickHouse
SIGNOZ_BASE_URL=http://signoz-query-service:8080
SIGNOZ_CLICKHOUSE_HOST=clickhouse
SIGNOZ_CLICKHOUSE_USER=default
SIGNOZ_CLICKHOUSE_PASSWORD=

# AI Agent
ANTHROPIC_API_KEY=sk-ant-...
LITELLM_BASE_URL=https://model-router.mcducklabs.com
LITELLM_MODEL=claude-sonnet-4-5-20250929

# Notifications (optional)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# CrowdSec (optional)
CROWDSEC_ENROLLMENT_KEY=
```

### Network Devices

Configure devices to send syslog to Docker host on port 514:

**pfSense:** Status → System Logs → Settings → Remote Logging
**UniFi:** Settings → System → Remote Logging
**QNAP:** Control Panel → System → System Logs → Syslog
**Proxmox:** Edit `/etc/rsyslog.conf`: `*.* @<docker-host-ip>:514`

## 🧪 Testing

```bash
# Test MCP server
python scripts/test_mcp_minimal.py

# List all tools
python scripts/test_mcp_list_tools.py

# Run integration tests
pytest tests/integration/ -v
```

## 📊 Monitoring

- **SigNoz UI:** http://localhost:3301 (dev) or port 8080 (prod)
- **MCP Health:** http://localhost:8082/health
- **Langfuse Traces:** https://cloud.langfuse.com (if configured)
- **Grafana Dashboards:** http://localhost:3000

## 🛣️ Roadmap

### ✅ Phase 1: DNS Security MVP (Complete)
- Hierarchical agent system
- 10 DNS security tools
- MCP server integration
- Claude Desktop interface
- Production deployment

### 🔜 Phase 2: Advanced Analytics
- Statistical anomaly detection engine
- Threat intelligence enrichment (AbuseIPDB, VirusTotal)
- Device inventory and tracking
- ntopng flow data integration
- Uptime monitoring integration

### 📋 Phase 3: Automation & Alerts
- Automated security reports
- Proactive threat notifications
- Historical trend analysis
- Predictive anomaly detection
- Automated remediation actions

## 🤝 Contributing

This is a personal homelab project, but feedback and suggestions are welcome!

## 📄 License

Private project - All rights reserved

## 🔗 Links

- [Model Context Protocol](https://modelcontextprotocol.io)
- [LangGraph](https://langchain-ai.github.io/langgraph/)
- [SigNoz](https://signoz.io)
- [Claude](https://claude.ai)

---

**Status:** ✅ **DNS Security MVP Complete**
**Deployed:** docker.mcducklabs.com:8082
**Last Updated:** March 7, 2026
