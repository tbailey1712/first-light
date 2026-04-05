# First Light

AI-powered network security and infrastructure observability for a home/prosumer network. Collects logs, metrics, and flow data from the full network stack, runs hierarchical AI domain agents to analyze everything daily, and delivers findings via Slack with interactive investigation support.

## Status

**Production — operational** on `docker.mcducklabs.com` (192.168.2.106)

| Component | Status |
|-----------|--------|
| Log ingestion (SigNoz/ClickHouse) | ✅ ~850k logs/day |
| Metrics ingestion | ✅ ~500k metrics/day |
| Daily report agent | ✅ Running nightly |
| Slack bot (interactive queries) | ✅ Deployed |
| MCP server (Claude Desktop) | ✅ Deployed |
| Threat intel enrichment | ✅ AbuseIPDB throttled to <1000/day |

## Architecture

```
Network Infrastructure
  pfSense · AdGuard · UniFi · QNAP · Proxmox · ntopng · Validators
       │
       ▼ syslog (TCP/UDP 5140) + Prometheus scrape
  OTel Collector (signoz-otel-collector)
  - Parses: pfSense filterlog, SSH/sudo, ntopng alerts, Proxmox, HA, Docker
  - Enriches: security attributes, VLAN tags, threat intel
       │
       ▼
  SigNoz / ClickHouse          Redis
  signoz_logs.logs_v2          fl:* keys (baseline metrics,
  signoz_metrics.*             conversation history, cache)
       │                            │
       ▼                            │
  LangGraph Daily Report Agent ◄────┘
  ┌─────────────────────────────────────────┐
  │  7 Domain Agents (concurrent)           │
  │  dns · firewall · infrastructure ·      │
  │  security · network · validator · cloud │
  │         ↓ structured JSON output        │
  │  Phase A: Suspicious item extraction    │
  │  Phase B: Investigation agent (tools)   │
  │  Phase C: Synthesis + final report      │
  └─────────────────────────────────────────┘
       │
       ▼
  Slack (#firstlight-reports · #firstlight-alerts)
  Slack Bot (interactive queries, threaded replies)
  MCP Server → Claude Desktop (natural language)
```

## Domain Agents

Each domain agent queries its data sources, produces a narrative + structured JSON (`---JSON-OUTPUT---` block with `overall_severity`, `findings[]`, `metrics{}`), then the graph merges findings and runs targeted investigation.

| Domain | Data Sources |
|--------|-------------|
| **dns** | AdGuard metrics (beaconing scores, TXT ratios, blocked domains, client risk) |
| **firewall** | pfSense filterlog, CrowdSec alerts |
| **infrastructure** | Proxmox, PBS backups, QNAP (SNMP + REST), Uptime Kuma, switch ports |
| **security** | SSH/sudo events (ClickHouse), threat intel enrichment, ntopng alerts |
| **network** | ntopng flows, UniFi APs, wireless health |
| **validator** | Nimbus/Nethermind metrics, attestation, beacon API |
| **cloud** | Cloudflare analytics, zone requests, Access policies |

## Tools

Tools are `@tool`-decorated functions available to domain and investigation agents.

| File | Tools |
|------|-------|
| `metrics.py` | AdGuard: top clients, block rates, high risk, threat signals, beaconing, TXT ratios, per-client blocked domains, new domains |
| `logs.py` | ClickHouse log search: security events, SSH brute force, sudo, hostname search, raw query |
| `ntopng.py` | Interfaces, active hosts, flows by host, alerts, L7 protocols, ARP, VLAN traffic, top countries, host details |
| `proxmox_tools.py` | Node stats, VM/CT list, backup status, VM configs |
| `pbs.py` | PBS datastore status, prune policies |
| `qnap_tools.py` | Health (SNMP fans/temps/disks + REST RAID), directory sizes |
| `cloudflare_tools.py` | Zone analytics, DNS records, Access apps |
| `crowdsec.py` | Metrics, hub status, decisions |
| `dns_tools.py` | Reverse DNS, FQDN lookup, topology resolution |
| `unifi_tools.py` | Client list, AP stats, MAC lookup |
| `validator.py` | Nimbus beacon REST, Nethermind metrics, attestation |
| `uptime_kuma.py` | Monitor definitions and status |
| `switch_tools.py` | Port status, VLAN membership |
| `threat_intel_tools.py` | AbuseIPDB enrichment (throttled) |
| `pfsense_dhcp.py` | DHCP lease lookup |
| `frigate.py` | Camera/NVR event queries |
| `investigation.py` | Cross-domain investigation synthesis |

## Exporters (custom, running on remote host)

| Container | Port | Purpose |
|-----------|------|---------|
| `fl-qnap-snmp-exporter` | 9003 | QNAP SNMP: temps, fans, disks, ZFS filesystems |
| `fl-qnap-api-exporter` | 9004 | QNAP REST API: volumes, RAID status |
| `fl-proxmox-exporter` | 9005 | Proxmox node/VM/CT/backup metrics |
| `fl-threat-intel-enricher` | — | AbuseIPDB enrichment sidecar |
| `fl-rsyslog` | 514 | Syslog ingestion relay |

## Network Topology

| VLAN | ID | Subnet | Purpose |
|------|----|--------|---------|
| Trusted LAN | 1 | 192.168.1.0/24 | Primary devices |
| IoT | 2 | 192.168.2.0/24 | Smart home, servers |
| CCTV | 3 | 192.168.3.0/24 | Cameras — isolated |
| DMZ/Validator | 4 | 192.168.4.0/24 | ETH validator nodes |
| Guest | 10 | 192.168.10.0/24 | Guest WiFi |

## Key Hosts

| Host | IP | Role |
|------|----|------|
| `docker.mcducklabs.com` | 192.168.2.106 | Docker host (all containers) |
| `pve.mcducklabs.com` | 192.168.2.5 | Proxmox hypervisor |
| `adguard.mcducklabs.com` | 192.168.2.x | AdGuard Home + analytics exporter |
| `vldtr.mcducklabs.com` | 192.168.4.2 | ETH validator (Nimbus + Nethermind) |
| `192.168.4.6` | — | Nimbus beacon REST API |

## Deployment

See [DEPLOY.md](DEPLOY.md) for the standard git-pull workflow.

**Local:** `/Users/tbailey/Dev/first-light` — development, git push
**Remote:** `/opt/first-light` on `docker.mcducklabs.com` — production, git pull + docker compose

```bash
# Deploy a change
git push origin feature/langgraph-redesign
ssh tbailey@192.168.2.106 "cd /opt/first-light && git pull && docker compose restart fl-agent fl-slack-bot"
```

## Slack Bot

- **`/firstlight <question>`** — ad-hoc investigation query
- **`@firstlight <question>`** — mention in any channel, threaded reply
- Reports posted to `#firstlight-reports`, alerts to `#firstlight-alerts`
- Conversation history via Redis (keyed by thread_ts, TTL 24h)

## MCP Server

Exposes agent tools to Claude Desktop via HTTP/SSE on port 8082.

```json
{
  "mcpServers": {
    "first-light": {
      "command": "mcp-proxy",
      "env": { "SSE_URL": "http://docker.mcducklabs.com:8082/sse" }
    }
  }
}
```

## Configuration

All secrets in `.env` on the remote host. Key variables:

```bash
ANTHROPIC_API_KEY=
LANGFUSE_PUBLIC_KEY=
LANGFUSE_SECRET_KEY=
SLACK_BOT_TOKEN=
SLACK_SIGNING_SECRET=
ABUSEIPDB_API_KEY=
CLICKHOUSE_HOST=signoz-clickhouse
CLICKHOUSE_PASSWORD=
REDIS_URL=redis://fl-redis:6379
NIMBUS_HOST=192.168.4.6
VALIDATOR_HOST=vldtr.mcducklabs.com
```

## Observability

- **SigNoz UI:** http://docker.mcducklabs.com:8080
- **Langfuse traces:** https://langfuse.mcducklabs.com (self-hosted)
- **Agent logs:** `docker logs -f fl-agent`
- **Slack bot logs:** `docker logs -f fl-slack-bot`

## Open Items

See [docs/PUNCHLIST.md](docs/PUNCHLIST.md) for current status.

Remaining open: INF-4 (CF Access on ntfy), INF-7 (vm/115 backup), INF-8 (CrowdSec metrics), INF-11 (SSH key-only on adguard/openclaw).
