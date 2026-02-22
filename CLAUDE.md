# NetOps AI — Self-Bootstrapping Network Observability Stack

## Project Identity

You are building **NetOps AI**, a unified network observability platform with AI-powered analysis. This project collects logs, metrics, and flow data from a home/prosumer network infrastructure, stores it in a modern observability stack, and uses an AI agent to analyze everything and communicate findings via Telegram.

## Architecture Overview

```
Data Sources → Grafana Alloy (collector) → VictoriaMetrics (metrics) + Loki (logs)
                                         → Grafana (dashboards)
                                         → CrowdSec (security)
                                         → LangGraph Agent (AI analysis)
                                         → Telegram Bot (interaction)
```

## Bootstrap Sequence

When this project is initialized, follow this exact sequence. **Do not skip steps. Do not assume anything. Probe and verify everything.**

### Phase 0: Project Scaffolding

Create the following directory structure:

```
netops-ai/
├── CLAUDE.md                          # This file
├── .env                               # All secrets (gitignored)
├── .env.example                       # Template without real values
├── .gitignore
├── docker-compose.yml
├── config/
│   ├── alloy/
│   │   └── config.alloy               # Grafana Alloy collector config
│   ├── loki/
│   │   └── loki-config.yml
│   ├── victoriametrics/
│   │   └── scrape.yml                 # Additional scrape configs if needed
│   ├── crowdsec/
│   │   ├── acquis.yaml                # Log acquisition config
│   │   └── profiles.yaml              # Alert profiles
│   ├── grafana/
│   │   └── provisioning/
│   │       ├── datasources/
│   │       │   └── datasources.yml    # Auto-provision VM + Loki
│   │       └── dashboards/
│   │           ├── dashboard.yml      # Dashboard provisioning config
│   │           └── json/              # Dashboard JSON files
│   └── ntfy/
│       └── server.yml                 # ntfy server config (if self-hosted)
├── agent/
│   ├── __init__.py
│   ├── graph.py                       # LangGraph agent definition
│   ├── scheduler.py                   # Cron-triggered analysis
│   ├── config.py                      # Loads .env + topology
│   ├── topology.yaml                  # Discovered network topology (generated)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── metrics.py                 # VictoriaMetrics PromQL queries
│   │   ├── logs.py                    # Loki LogQL queries
│   │   ├── ntopng.py                  # ntopng REST API
│   │   ├── crowdsec.py                # CrowdSec LAPI
│   │   ├── validator.py               # ETH beacon chain API
│   │   ├── adguard.py                 # AdGuard Home API
│   │   ├── uptime.py                  # Uptime Kuma API
│   │   ├── pfsense.py                 # pfSense API (if available)
│   │   └── notify.py                  # Notification dispatch
│   └── prompts/
│       ├── __init__.py
│       ├── system.py                  # Base system prompts
│       ├── analysis.py                # Anomaly analysis prompts
│       ├── digest.py                  # Scheduled digest prompts
│       └── interactive.py             # Telegram Q&A prompts
├── bot/
│   ├── __init__.py
│   ├── telegram_bot.py                # Telegram bot
│   └── formatters.py                  # Response formatting
├── exporters/
│   ├── __init__.py
│   └── adguard_exporter.py            # AdGuard metrics exporter (if needed)
├── scripts/
│   ├── probe_network.py               # Network discovery script
│   ├── test_connections.py            # Verify all data source connections
│   ├── generate_configs.py            # Generate configs from topology
│   └── setup_pfsense_syslog.sh        # Instructions/automation for pfSense
├── requirements.txt
└── README.md
```

Create all directories and placeholder files first. Then proceed to Phase 1.

### Phase 1: Network Discovery

**This is interactive. Ask the user questions and probe their network.**

#### Step 1.1: Determine the Docker Host

Ask the user:
- "What host will run this stack? Give me the IP or hostname."
- "How much RAM is available for this stack?"
- "Where should persistent data live? (default: /opt/netops-ai/data)"
- "What's the timezone? (default: America/Chicago)"

Verify the host is reachable. Check available disk space and RAM if running locally.

#### Step 1.2: Discover pfSense

Ask: "What's your pfSense IP or hostname?"

Then probe:
- Try to reach the pfSense web UI (typically port 443 or 8443)
- Check if pfSense API is available: `curl -sk https://<ip>/api/v1/system/info`
- If API is available, ask for API key and secret
- If API is not available, note that we'll use syslog only
- Ask: "Is pfSense already sending syslog somewhere, or should I configure a new destination?"
- Determine pfSense version if possible (CE vs Plus, version number — affects API availability)

Store findings in `agent/topology.yaml`.

#### Step 1.3: Discover AdGuard Home

Ask: "What's your AdGuard Home IP and port? (default port: 3000 or 80)"

Then probe:
- Hit `http://<ip>:<port>/control/status` to verify it's AdGuard
- If auth required, ask for username and password
- Test API access: `http://<ip>:<port>/control/stats`
- Check if query log is enabled: `http://<ip>:<port>/control/querylog_info`
- Note the API capabilities available

#### Step 1.4: Discover ntopng

Ask: "What's your ntopng IP and port? (default: 3000)"

Then probe:
- Hit `http://<ip>:<port>/lua/rest/v2/get/ntopng/interfaces.lua` or similar
- Ask for API credentials if needed
- Enumerate monitored interfaces
- Check which protocols/features are enabled (flow export, historical data, etc.)
- Note the ntopng version (Community vs Enterprise — affects API availability)

#### Step 1.5: Discover the Switch

Ask: "What's your managed switch IP? What model is it?"

Then probe:
- Try SNMP v2c with common community strings ("public", "private")
- If that fails, ask for SNMP credentials
- Walk key OIDs to determine:
  - System description (sysDescr)
  - Number of ports (ifNumber)
  - VLAN configuration if available via SNMP
  - Port names/descriptions
- Ask: "How many VLANs do you have and what are they used for?"
- For each VLAN, get: ID, name, subnet, purpose, security level

**Requires:** `pip install pysnmp` or use `snmpwalk` via subprocess.

#### Step 1.6: Discover Ubiquiti

Ask: "What's your UniFi Controller IP and port? (default: 8443)"

Then probe:
- Try to hit the UniFi API: `https://<ip>:<port>/api/login`
- Ask for controller credentials
- Enumerate sites, then APs per site
- Get AP names, MACs, locations, models
- Check if syslog is already configured on the controller

#### Step 1.7: Discover Uptime Kuma

Ask: "What's your Uptime Kuma IP and port? (default: 3001)"

Then probe:
- Check if Prometheus metrics endpoint exists: `http://<ip>:<port>/metrics`
- If available, note what monitors are configured
- Check API availability
- Ask for API key if needed

#### Step 1.8: Discover ETH Validator

Ask: "What consensus client are you running? (Lighthouse, Prysm, Teku, Nimbus, Lodestar)"
Ask: "What execution client? (Geth, Nethermind, Besu, Erigon)"
Ask: "What host runs the validator? Give me the IP."

Then probe:
- Try consensus client metrics: `http://<ip>:5054/metrics` (Lighthouse default), adjust port per client
- Try beacon API: `http://<ip>:5052/eth/v1/node/version`
- Try execution client metrics: `http://<ip>:6060/debug/metrics/prometheus` (Geth) or equivalent
- Verify peer count, sync status
- Ask for validator public key(s) for on-chain monitoring

#### Step 1.9: Discover Additional Hosts

Ask: "Are there other servers or machines you want monitored for CPU/RAM/disk? List their IPs and roles."

For each host:
- Check if node_exporter is running: `http://<ip>:9100/metrics`
- Check if SNMP is available
- If neither, note that Alloy agent will need to be installed on that host

#### Step 1.10: Collect Secrets and Preferences

Ask for all remaining secrets:
- "Anthropic API key for the AI agent"
- "Telegram bot token (create one via @BotFather if you don't have one)"
- "Your Telegram chat ID (send a message to @userinfobot to get it)"
- "Do you want email notifications? If so, SMTP details."
- "Do you want to use ntfy for push notifications? Self-hosted or ntfy.sh?"
- "Do you have a CrowdSec console enrollment key? (optional, free at app.crowdsec.net)"

Store ALL secrets in `.env` file, never in config files. Reference them as `${VARIABLE_NAME}` everywhere.

### Phase 2: Generate Configurations

Using everything discovered in Phase 1, generate all configuration files.

#### Step 2.1: docker-compose.yml

Generate a complete Docker Compose file with these services:
- **victoriametrics**: `victoriametrics/victoria-metrics:stable` — port 8428, persistent storage
- **loki**: `grafana/loki:3.4.2` (or latest stable) — port 3100, persistent storage
- **alloy**: `grafana/alloy:latest` — syslog listener ports, host network mode for SNMP
- **grafana**: `grafana/grafana:latest` — port 3000 (or next available if 3000 conflicts with existing services), persistent storage, provisioned datasources
- **crowdsec**: `crowdsec/crowdsec:latest` — reads pfSense logs from Loki or direct syslog
- **redis**: `redis:7-alpine` — for agent state caching
- **agent**: build from `./agent` Dockerfile — depends on VM, Loki, Redis
- **bot**: build from `./bot` Dockerfile — depends on agent
- **ntfy** (if self-hosted): `binwiederhier/ntfy:latest`

Important considerations:
- Map ports carefully. Check for conflicts with existing services (AdGuard on 3000, ntopng on 3000, Uptime Kuma on 3001, etc.). Pick non-conflicting ports for Grafana and other stack services.
- Use `.env` file for all secrets via `env_file` directive
- Set memory limits appropriate to available RAM
- Use named volumes for persistence
- Set restart policies to `unless-stopped`
- Pin image versions, don't use `latest` in final config (look up current stable versions)

#### Step 2.2: Grafana Alloy config

Generate `config/alloy/config.alloy` using Alloy's River configuration language. Include:

For each discovered data source, configure the appropriate Alloy components:

**Syslog receivers:**
```
// pfSense syslog
loki.source.syslog "pfsense" {
  listener {
    address  = "0.0.0.0:<port>"
    protocol = "udp"
    labels   = { source = "pfsense" }
  }
  forward_to = [loki.process.pfsense.receiver]
}

// pfSense log processing - parse filterlog format
loki.process "pfsense" {
  // Add stage to parse pfSense CSV filterlog format
  // Extract: action, direction, interface, protocol, src_ip, dst_ip, src_port, dst_port
  forward_to = [loki.write.default.receiver]
}
```

Add similar blocks for Ubiquiti AP syslog (on a different port).

**SNMP polling:**
```
// Switch SNMP
prometheus.scrape "switch_snmp" {
  // Use snmp_exporter or telegraf sidecar for SNMP → Prometheus conversion
}
```

Note: Alloy doesn't have native SNMP polling. We need an `snmp_exporter` sidecar container in docker-compose. Generate the snmp.yml config for the specific switch model.

**Prometheus scrape targets:**
For each discovered Prometheus endpoint (validator, Uptime Kuma, node_exporters):
```
prometheus.scrape "<name>" {
  targets = [{"__address__" = "<ip>:<port>"}]
  forward_to = [prometheus.remote_write.victoriametrics.receiver]
  scrape_interval = "30s"
}
```

**Remote write to VictoriaMetrics:**
```
prometheus.remote_write "victoriametrics" {
  endpoint {
    url = "http://victoriametrics:8428/api/v1/write"
  }
}
```

**Log output to Loki:**
```
loki.write "default" {
  endpoint {
    url = "http://loki:3100/loki/api/v1/push"
  }
}
```

#### Step 2.3: Loki config

Generate `config/loki/loki-config.yml` with:
- Filesystem storage backend (simple for self-hosted)
- Retention period from user preferences (default 90 days)
- Appropriate limits for ingestion rate
- Compaction settings

#### Step 2.4: Grafana provisioning

Generate datasource provisioning that auto-configures:
- VictoriaMetrics as a Prometheus-type datasource
- Loki as a Loki-type datasource

Generate starter dashboards:
- Network Overview (traffic per VLAN, top talkers summary)
- Security (pfSense blocks, CrowdSec alerts, AdGuard blocks)
- ETH Validator (attestation effectiveness, balance, peer count, sync status)
- Infrastructure Health (disk, CPU, memory across all hosts)

Use community dashboard JSON where available (especially for ETH validator monitoring — search for Lighthouse/Prysm Grafana dashboards).

#### Step 2.5: CrowdSec config

Generate `config/crowdsec/acquis.yaml` to watch pfSense log sources (from Loki or direct syslog tap).

#### Step 2.6: Agent topology file

Write `agent/topology.yaml` with all discovered network information — this becomes the agent's understanding of the network. Include:
- All devices with IPs, ports, capabilities
- VLAN layout with security levels
- Normal patterns noted by the user
- Alert thresholds

### Phase 3: Build the AI Agent

#### Step 3.1: Agent tools

For each data source discovered in Phase 1, generate the corresponding tool in `agent/tools/`. Each tool should:

- Connect to the data source's API
- Have well-typed input/output schemas
- Include error handling and timeout management
- Load connection details from `agent/config.py` which reads from `.env` and `topology.yaml`

Common tool pattern:
```python
import httpx
from langchain_core.tools import tool
from agent.config import get_config

@tool
def query_victoriametrics(promql_query: str, start: str = "1h", step: str = "5m") -> str:
    """Execute a PromQL query against VictoriaMetrics.
    
    Args:
        promql_query: PromQL query string
        start: Lookback period (e.g., "1h", "6h", "24h")
        step: Query resolution step
    
    Returns:
        JSON string of query results
    """
    config = get_config()
    # Implementation here
```

#### Step 3.2: LangGraph agent graph

Generate `agent/graph.py` with a ReAct-style agent that:
- Takes a question or analysis request
- Has access to all tools
- Reasons about which data sources to query
- Synthesizes findings across sources
- Produces actionable recommendations

The graph should support two modes:
1. **Scheduled analysis** — broad sweep of all data sources, produce a digest
2. **Interactive query** — answer a specific question from the user via Telegram

#### Step 3.3: Prompt engineering

Generate prompts in `agent/prompts/` that:
- Describe the network topology to the LLM (loaded from topology.yaml)
- Define what "normal" looks like
- Specify severity classifications
- Format output for Telegram (markdown, concise, actionable)
- Include the VLAN layout and security levels so the AI can reason about cross-VLAN traffic

System prompt should include:
```
You are NetOps AI, a network security and infrastructure analyst for a home/prosumer network.

Network topology:
{topology_summary}

Your job is to:
1. Identify security anomalies (unusual traffic, blocked intrusion attempts, new unknown devices)
2. Monitor infrastructure health (disk space, network port utilization, service availability)
3. Track ETH validator performance (attestation effectiveness, missed proposals, peer count)
4. Correlate events across data sources (e.g., DNS blocks + firewall blocks from same source)
5. Provide actionable recommendations

Severity levels:
- CRITICAL: Active security threat, service down, validator offline, disk full
- WARNING: Unusual pattern, degraded performance, approaching thresholds
- INFO: Notable events, routine summaries, positive confirmations

Always be specific. Include IPs, timestamps, and affected VLANs. Suggest concrete next steps.
```

#### Step 3.4: Scheduler

Generate `agent/scheduler.py` using APScheduler or similar:
- Quick health check every 30 minutes (lightweight — just check for criticals)
- Full analysis digest every 6 hours
- Both send results to configured notification channels

### Phase 4: Build the Telegram Bot

Generate `bot/telegram_bot.py` with:

**Commands:**
- `/status` — quick health check of all systems
- `/digest` — trigger a full analysis now
- `/ask <question>` — ask the AI agent anything about the network
- `/alerts` — show recent alerts/anomalies
- `/validator` — ETH validator status summary
- `/vlans` — traffic summary per VLAN
- `/help` — list commands

**Conversational mode:**
- Any message without a command prefix gets routed to the AI agent as a natural language query
- Support multi-turn conversation (use Redis for conversation state)
- Send typing indicators while the agent works

**Security:**
- Only respond to allowed Telegram user IDs (from .env)
- Log all interactions

### Phase 5: Testing and Startup

#### Step 5.1: Connection testing

Generate `scripts/test_connections.py` that:
- Tests every data source discovered in Phase 1
- Verifies API credentials work
- Checks that syslog ports are not already in use
- Validates SNMP connectivity
- Reports a clear pass/fail for each source with troubleshooting hints

#### Step 5.2: Startup sequence

1. Run `scripts/test_connections.py` — fix any failures before proceeding
2. `docker compose up -d victoriametrics loki grafana` — start storage and visualization first
3. Wait for healthy status on all three
4. `docker compose up -d alloy` — start the collector
5. Verify data is flowing into Grafana (check datasource health in Grafana UI)
6. `docker compose up -d crowdsec redis` — start security and cache
7. `docker compose up -d agent bot` — start the AI layer
8. Send a test message to the Telegram bot

#### Step 5.3: Provide setup instructions for device-side config

Generate `scripts/setup_pfsense_syslog.sh` (really a markdown doc with screenshots/steps) explaining:
- How to enable remote syslog on pfSense (Status → System Logs → Settings → Remote Logging)
- What IP and port to send to
- How to enable AdGuard query logging if not already on
- How to configure syslog on the UniFi Controller
- How to enable SNMP on the switch (model-specific)

## Coding Standards

- Python 3.12+
- Use `httpx` for async HTTP, not `requests`
- Use `pydantic` for all configuration models
- Use `python-dotenv` for environment variable loading
- Type hints on all functions
- Docstrings on all public functions and classes
- Error handling: never crash on a single data source failure — log the error and continue with other sources
- All secrets via environment variables, never hardcoded
- Use `structlog` for structured logging throughout

## Dependencies

```
# Core
langgraph>=0.2.0
langchain-anthropic>=0.3.0
langchain-core>=0.3.0
httpx>=0.27.0
pydantic>=2.0
pydantic-settings>=2.0
python-dotenv>=1.0
structlog>=24.0
redis>=5.0
apscheduler>=3.10

# Telegram
python-telegram-bot>=21.0

# Network discovery
pysnmp>=6.0

# Utilities
pyyaml>=6.0
jinja2>=3.1
tenacity>=8.0
```

## Key Principles

1. **Discover, don't assume.** Probe every endpoint. Verify every connection. Ask the user when probing fails.
2. **Degrade gracefully.** If a data source is unreachable, the rest of the stack should still work. The AI agent should note what's unavailable and work with what it has.
3. **Secrets stay in .env.** Nothing sensitive in config files, topology files, or code.
4. **Ask, don't guess.** If something is ambiguous (port conflicts, VLAN purposes, alert thresholds), ask the user.
5. **Test before you deploy.** Run connection tests before starting the stack. Verify data is flowing before starting the AI layer.
6. **Progressive enhancement.** Get basic data flowing first. Add AI analysis second. Add agentic actions later.

## Future Enhancements (Phase 6+, not for initial build)

- MCP servers for each data source (allow any LLM to query the network)
- Agentic actions: block IPs on pfSense, quarantine devices to restricted VLAN
- Home Assistant integration (correlate network events with physical events)
- Grafana annotations from AI agent findings
- Weekly trend reports with month-over-month comparisons
- Anomaly detection model trained on your specific network patterns
