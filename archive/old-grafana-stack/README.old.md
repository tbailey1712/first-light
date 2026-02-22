# First Light

**AI-powered network observability that tells you what matters**

First Light is a self-bootstrapping network observability platform that combines metrics, logs, and flow data from your network infrastructure with AI-powered analysis to deliver actionable insights via Telegram.

## Architecture

```
Data Sources → Grafana Alloy (collector) → VictoriaMetrics (metrics) + Loki (logs)
                                         → Grafana (dashboards)
                                         → CrowdSec (security)
                                         → LangGraph Agent (AI analysis)
                                         → Telegram Bot (interaction)
```

## Supported Data Sources

- **pfSense**: Firewall logs and metrics
- **AdGuard Home**: DNS query logs and blocking statistics
- **ntopng**: Network flow data and traffic analysis
- **Managed Switches**: SNMP metrics (ports, VLANs, throughput)
- **UniFi Controller**: Access point metrics and client data
- **Uptime Kuma**: Service availability monitoring
- **Ethereum Validator**: Consensus and execution client metrics
- **Generic Hosts**: CPU, RAM, disk via node_exporter or SNMP

## Quick Start

1. **Network Discovery**: Run the interactive setup to discover your network devices
2. **Configuration**: Generate all configs based on your network topology
3. **Deploy**: Start the Docker stack
4. **Interact**: Chat with your network via Telegram

## Setup

See [CLAUDE.md](CLAUDE.md) for complete bootstrap instructions.

## Key Features

- 🔍 **Automatic Discovery**: Probes your network and configures itself
- 🤖 **AI Analysis**: LangGraph-powered agent correlates data across sources
- 📱 **Telegram Interface**: Ask questions, get alerts, trigger analysis
- 📊 **Unified Dashboards**: Pre-configured Grafana dashboards
- 🔒 **Security Focus**: CrowdSec integration, anomaly detection
- ⚡ **ETH Validator Monitoring**: Track validator performance and earnings

## Tech Stack

- **Grafana Alloy**: Telemetry collection
- **VictoriaMetrics**: Time-series metrics storage
- **Loki**: Log aggregation
- **Grafana**: Visualization
- **CrowdSec**: Security intelligence
- **LangGraph**: AI agent orchestration
- **Anthropic Claude**: Large language model
- **Python**: Agent and bot implementation

## License

MIT

---

Built with Claude Code
