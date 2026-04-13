# First Light — AI-Powered Network Security Platform

## Project Identity

**First Light** is a production AI-powered network security and infrastructure observability platform for a home/prosumer network. It collects logs, metrics, and flow data from the full network stack, runs concurrent hierarchical AI domain agents to analyze everything daily, and delivers structured findings via Slack with interactive investigation support.

The project name is **First Light** (not NetOps AI). The Slack bot is the primary interface (not Telegram).

---

## Network Device Reference

**`docs/dhcp_leases.md`** contains the complete DHCP lease table for the entire network — every device's IP, MAC address, hostname, and notes. **Always check this file first** before asking the user to identify a device or before assuming an IP is unknown. Never ask the user to identify a device that could be looked up here.

---

## Current Status (April 2026)

**Infrastructure:** ✅ Deployed and operational
- SigNoz (ClickHouse backend) collecting ~850k logs/day, ~500k metrics/day
- OTel Collector with comprehensive log parsing (pfSense filterlog, SSH/sudo, ntopng, Proxmox, HA, Docker)
- Telegraf for SNMP metrics: TP-Link switch, QNAP (fans/temps/disks/filesystems), Proxmox
- AbuseIPDB threat intel enrichment (throttled to <1000 req/day via `threat-intel-enricher` service)
- rsyslog fan-out: UDP/TCP 514 → SigNoz OTel + CrowdSec log files
- CrowdSec detection-only (pfSense bouncer **not** installed — detects but cannot enforce bans)

**AI Agent:** ✅ Production — running nightly
- 8 concurrent domain agents (firewall_threat, dns_security, network_flow, infrastructure, wireless, validator, cloudflare, home_automation)
- Structured JSON output (`---JSON-OUTPUT---` blocks) from all domain agents
- LangGraph graph: initialize → run_domains_parallel → correlate → synthesize → END
- Baseline metrics tracked in Redis across daily runs
- All LLM calls traced in Langfuse (project: `first-light`)

**Slack Bot:** ✅ Deployed (`slack-bot` service)
- `/firstlight <question>` slash command
- `@firstlight` mention with threaded replies
- Reports to `#firstlight-reports`, alerts to `#home-network`
- Conversation history via Redis (thread_ts keyed, TTL 24h)

**MCP Server:** ✅ Deployed (`mcp-server` service, port 8082) — Claude Desktop integration

**Active branch:** `feature/langgraph-redesign`

---

## Architecture Overview

```
Network Infrastructure
  pfSense · AdGuard · UniFi · QNAP · Proxmox · ntopng · ETH Validator · Home Assistant
       │
       ├─ syslog TCP/UDP 514 ──► rsyslog fan-out ──► OTel Collector ──► SigNoz/ClickHouse
       │                                         └──► CrowdSec (log files)
       ├─ SNMP ──────────────────────────────────► Telegraf ──────────► SigNoz/ClickHouse
       └─ REST APIs ──────────────────────────────► Agent tools (direct queries)

SigNoz/ClickHouse (logs + metrics)
  └─► LangGraph Daily Report Agent
        ├─ initialize          (fetch Langfuse prompts, load Redis baseline)
        ├─ run_domains_parallel (8 domain agents concurrently via ThreadPoolExecutor)
        ├─ correlate            (cross-domain IP/device lookups)
        └─ synthesize           (final report, save baseline to Redis)
              └─► Slack Bot (#firstlight-reports)
              └─► MCP Server (Claude Desktop)
```

### Graph Details (`agent/graphs/daily_report_graph.py`)

| Node | What it does |
|---|---|
| `initialize` | Fetches all Langfuse prompts, loads Redis baselines, sets run metadata |
| `run_domains_parallel` | Fans out all 8 domain agents via `ThreadPoolExecutor`; each agent runs a ReAct loop with tools |
| `correlate` | Cross-domain correlation pass — IPs/devices flagged in multiple domains get linked |
| `synthesize` | Final synthesis LLM call → structured Slack report, severity headline, recommendations |

Domain agents and their Langfuse prompt names:

| Agent key | Langfuse prompt |
|---|---|
| `firewall_threat` | `first-light-firewall-threat` |
| `dns_security` | `first-light-dns` |
| `network_flow` | `first-light-network-flow` |
| `infrastructure` | `first-light-infrastructure` |
| `wireless` | `first-light-wireless` |
| `validator` | `first-light-validator` |
| `cloudflare` | `first-light-cloudflare` |
| `home_automation` | `first-light-home-automation` |
| — | `first-light-synthesis` |
| — | `first-light-correlation` |
| — | `first-light-investigation` |

---

## Docker Services

All services run on `docker.mcducklabs.com` (192.168.2.106) at `/opt/first-light`.

| Compose service | Container name | Purpose |
|---|---|---|
| `agent` | `fl-agent` | Daily report scheduler + MCP host |
| `slack-bot` | `fl-slack-bot` | Slack slash command + mention handler |
| `mcp-server` | `fl-mcp-server` | MCP server on port 8082 |
| `redis` | `fl-redis` | Baselines, conversation history, locks |
| `threat-intel-enricher` | `fl-threat-intel-enricher` | AbuseIPDB lookup sidecar |
| `rsyslog` | `fl-rsyslog` | Syslog fan-out (514 UDP/TCP) |
| `telegraf-snmp` | `fl-telegraf-snmp` | SNMP metrics collection |
| `crowdsec` | `fl-crowdsec` | Threat detection (detection-only) |
| `telegram-bot` | — | Legacy; not the primary interface |
| `ui` | — | Homepage dashboard (gethomepage.dev v1.3.2) |
| `webhook-relay` | — | Webhook ingress relay |

SigNoz stack services (defined in `signoz/docker-compose.yaml`, included via `include:`):
- `signoz-otel-collector` — log/metric ingestion
- `signoz-query-service` — ClickHouse query API
- `signoz-frontend` — SigNoz UI

**IMPORTANT:** The compose service name is `agent` (not `fl-agent`). Container names have the `fl-` prefix. Restart commands use the service name:
```bash
docker compose restart agent slack-bot
```

---

## Tool Inventory (`agent/tools/`)

| File | What it covers |
|---|---|
| `logs.py` | ClickHouse log queries via SigNoz HTTP API — firewall blocks, DNS queries, auth events, container logs, outbound blocks, syslog search |
| `metrics.py` | ClickHouse metrics queries — CPU, RAM, disk, network throughput, SNMP interface stats |
| `ntopng.py` | ntopng REST API — flow data, top talkers, host details, alerts, protocol breakdown |
| `proxmox_tools.py` | Proxmox VE API — VM/LXC status, resource usage, node health |
| `pbs.py` | Proxmox Backup Server API — backup job status, datastore usage |
| `qnap_tools.py` | QNAP NAS API — volume health, disk SMART, system stats |
| `switch_tools.py` | TP-Link SG2424 SNMP — port stats, errors, utilization |
| `infra_health.py` | Infrastructure health aggregator — log ingestion freshness, metrics staleness checks |
| `validator.py` | ETH beacon chain API — attestation effectiveness, sync status, peer count, balance |
| `adguard.py` | AdGuard Home API — query stats, blocked domains, client activity, TXT ratio |
| `threat_intel_tools.py` | AbuseIPDB lookups — IP reputation, abuse confidence score, ISP/country |
| `cloudflare_tools.py` | Cloudflare API — tunnel status, firewall events, zone analytics |
| `dns_tools.py` | DNS resolution utilities — reverse lookups, domain age checks |
| `unifi_tools.py` | UniFi Controller API — AP status, client counts, wireless health |
| `ha_tools.py` | Home Assistant API — entity states, event history, device presence |
| `frigate.py` | Frigate NVR API — camera status, detection events, recording stats |
| `pfsense_dhcp.py` | pfSense DHCP leases via XML-RPC — active leases, unknown clients |
| `crowdsec.py` | CrowdSec LAPI — active decisions, alerts, hub scenario status |
| `investigation.py` | Investigation utilities — cross-tool correlation helpers |
| `uptime_kuma.py` | Uptime Kuma — monitor status via SQLite direct query |

---

## ClickHouse Gotchas

- **JSONEachRow returns all integers as strings.** Always cast with `int()` before arithmetic: `int(row["block_count"])`. This caused `TypeError: unsupported operand type(s) for +=: 'int' and 'str'` in `query_outbound_blocks` (fixed).
- **Default query timeout is 30 seconds.** Long aggregation queries against distributed tables will timeout. Add `max_execution_time: 12` to health check queries. Use `LIMIT` aggressively.
- **Use distributed table names** (`signoz_logs.distributed_logs`, `signoz_metrics.distributed_*`) for cross-shard queries. Direct shard tables may return partial results.
- **SigNoz HTTP API endpoint:** `http://signoz-query-service:8085/api/v1/query_range` for metrics; ClickHouse HTTP at port 9001 for raw SQL.
- **Log attribute access:** `log.body` and `log.attributes["x"]` in OTTL transforms (not deprecated `body`/`attributes["x"]`).

---

## Active Work

### EPIC_FL_EVAL_001 — Langfuse Eval Lifecycle
**Status:** Architecture designed, no code written yet.
**Spec:** `docs/EPIC_FL_EVAL_001.md`
**Goal:** Pull historical daily report traces from Langfuse, replay synthesis step against multiple model variants (sonnet-4-6 vs opus-4-6), judge output quality with LLM-as-judge, detect regressions, post Slack summary.

Planned file structure under `agent/evals/`:
- `eval_agent.py` — LangGraph graph
- `state.py`, `config.py`, `registry.py` — state/config/Redis
- `trace_extractor.py` — extract SynthesisInput from Langfuse traces
- `synthesis_replayer.py` — task_fn factory for `langfuse.run_experiment()`
- `judge.py` — LLM-as-judge (opus-4-6), 5-dimension rubric
- `nodes/` — 6 graph nodes

Key risk: synthesis observation name is `"synthesis"` type `"GENERATION"` — if span name changes, extractor breaks.

### Homepage Dashboard (`~/homepage/` on remote)
**Status:** Mostly functional. Remaining widget errors:
- UniFi — creds issue (`hassio/hassio` was wrong default)
- Portainer — API key 401
- Uptime Kuma — slug `default` may need adjustment
- HA widget — verify `ha.mcducklabs.com:8123` is resolving correctly

Homepage CSS lives at `~/homepage/custom.css` on remote (not in this repo). Key selectors:
- Section headers: `.service-group-name`
- Service error banners: `summary[class*="bg-rose"]`
- Background: `html, body, #__next`, `#page_wrapper`, `#inner_wrapper`

### Open Investigation Items
See `docs/PUNCHLIST.md` for deferred items. Current open items:
- Port 17 (Proxmox) NIC V2 discards — check `ethtool eth2` for duplex mismatch
- ETH validator UDP/30303 outbound — verify VLAN 4 egress rule allows UDP/30303 for Geth P2P
- pfBlockerNG Reputation feeds — add Emerging Threats/Firehol to catch scanning infrastructure (e.g., Kaopu Cloud AS136557)
- CrowdSec pfSense bouncer — install to enable enforcement (currently detection-only)

---

## Deployment Workflow

**CRITICAL: This project has a LOCAL/REMOTE split.**

**LOCAL (Development):**
- Path: `/Users/tbailey/Dev/first-light`
- Code development and git commits only
- Do NOT run docker-compose here

**REMOTE (Production):**
- Hostname: `docker.mcducklabs.com` / IP: `192.168.2.106`
- Path: `/opt/first-light`
- All Docker operations happen here

### Standard Deploy

```bash
# LOCAL: commit and push
git add <files>
git commit -m "description"
git push origin feature/langgraph-redesign

# REMOTE: pull and restart
ssh tbailey@192.168.2.106 "cd /opt/first-light && git pull && docker compose restart agent slack-bot"

# REMOTE: rebuild with dependency changes
ssh tbailey@192.168.2.106 "cd /opt/first-light && git pull && docker compose up -d --build agent slack-bot"
```

### Key Notes

- **Use `docker compose` (v2)** — not `docker-compose` (v1 has ContainerConfig bug with newer Docker)
- **Compose service name is `agent`** — container is named `fl-agent`
- **Langfuse prompts:** Run `python3 scripts/push_all_prompts.py` locally, not via docker exec
- **Never push all Langfuse prompts at once** — fetch from Langfuse first and update only the specific prompt being changed
- **Never SSH to pfSense (192.168.1.1)** — use XML-RPC over HTTPS only

### Quick Reference

```bash
# What's running
ssh tbailey@192.168.2.106 "docker ps --filter 'name=fl-'"

# Agent logs
ssh tbailey@192.168.2.106 "docker logs -f fl-agent"

# OTel collector health
ssh tbailey@192.168.2.106 "docker logs signoz-otel-collector 2>&1 | grep -E 'ready|error|fatal' | tail -5"

# Trigger report manually
ssh tbailey@192.168.2.106 "docker exec fl-agent python -c 'import asyncio; from agent.graphs.daily_report_graph import generate_daily_report; asyncio.run(generate_daily_report())'"
```

---

## OTel Collector OTTL Constraints (v0.142.0)

The SigNoz OTel collector build has constraints that differ from upstream:

- Use `log.body` and `log.attributes["x"]` — not deprecated `body` / `attributes["x"]`
- **`IsPresent()` is NOT available** — use `IsMatch(log.body, "pattern")` guards instead
- **`attributes["x"] == nil` throws** a `StandardPMapGetter` type error — always use `IsMatch` body guards
- Keep `error_mode: ignore` on transform processors
- The OpAMP server pushes config to `/var/tmp/collector-config.yaml` — config parse errors cause rollback

---

## Network Topology (Summary)

Full device list: **`docs/dhcp_leases.md`**

| VLAN | Subnet | Purpose | Trust level |
|---|---|---|---|
| 1 | 192.168.1.0/24 | Trusted LAN — servers, workstations | High |
| 2 | 192.168.2.0/24 | IoT — smart home devices | Low; DHCP now "known clients only" |
| 3 | 192.168.3.0/24 | CCTV — cameras isolated | None (no inter-VLAN routing) |
| 4 | 192.168.4.0/24 | DMZ — validator, jumpbox | None (outbound only) |
| 10 | 192.168.10.0/24 | Guest WiFi | None |

Key fixed IPs:
- `192.168.1.1` — pfSense (Netgate 3100)
- `192.168.2.9` — QNAP TS-462 (port 8080 for API, not through NPM)
- `192.168.2.7` — Frigate NVR (port 5000 — use direct IP, not `frigate.mcducklabs.com`)
- `192.168.2.106` — Docker host (docker.mcducklabs.com)
- `192.168.4.2` — ETH validator (vldtr)

**Frigate:** Always use `http://192.168.2.7:5000` directly. `frigate.mcducklabs.com` is an NPM proxy with basic auth that breaks API widgets.
**QNAP:** Always use `http://192.168.2.9:8080` directly. The NPM proxy breaks session auth.
**Home Assistant:** `https://ha.mcducklabs.com:8123` (there is no `hass.mcducklabs.com`).
**pfSense:** Never SSH. XML-RPC over HTTPS only.

---

## Coding Standards

- Python 3.12+
- `httpx` for async HTTP
- `pydantic` for configuration models
- Type hints on all functions
- Never crash on a single data source failure — log and continue
- All secrets via environment variables, never hardcoded
- ClickHouse JSONEachRow: always `int()` cast numeric fields before arithmetic
