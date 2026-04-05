# First Light — Deployment Guide

## Environment Split

| Environment | Host | Path | Purpose |
|-------------|------|------|---------|
| Local | `tbailey's Mac` | `/Users/tbailey/Dev/first-light` | Development, git commits, push |
| Remote | `docker.mcducklabs.com` (192.168.2.106) | `/opt/first-light` | Production, git pull, docker compose |

**Never run docker compose locally. Never push from remote.**

SSH access is passwordless: `ssh tbailey@192.168.2.106`

---

## Standard Deploy Workflow

```bash
# 1. LOCAL — commit and push
git add <files>
git commit -m "description"
git push origin feature/langgraph-redesign

# 2. REMOTE — pull and restart affected services
ssh tbailey@192.168.2.106 "cd /opt/first-light && git pull origin feature/langgraph-redesign && docker compose restart <service>"
```

### Which services to restart

| Changed files | Restart |
|---------------|---------|
| `agent/` (tools, graphs, prompts) | `fl-agent fl-slack-bot` |
| `signoz/otel-collector-config.yaml` | `signoz-otel-collector` |
| `exporters/qnap-snmp/` | `fl-qnap-snmp-exporter` |
| `exporters/qnap-api/` | `fl-qnap-api-exporter` |
| `exporters/proxmox/` | `fl-proxmox-exporter` |
| `exporters/threat-intel-enricher/` | `fl-threat-intel-enricher` |
| `bot/slack_bot.py` | `fl-slack-bot` |

For changes that require a full image rebuild (new Python dependencies):
```bash
ssh tbailey@192.168.2.106 "cd /opt/first-light && git pull && docker compose up -d --build fl-agent fl-slack-bot"
```

---

## Running Containers

```
fl-agent                  Daily report agent (LangGraph)
fl-slack-bot              Slack bot (Socket Mode)
fl-mcp                    MCP server (Claude Desktop, port 8082)
fl-redis                  Redis (conversation history, baseline cache)
fl-crowdsec               CrowdSec (threat detection)
fl-rsyslog                Syslog relay (port 514)
fl-qnap-snmp-exporter     QNAP SNMP metrics (port 9003)
fl-qnap-api-exporter      QNAP REST API metrics (port 9004)
fl-proxmox-exporter       Proxmox metrics (port 9005)
fl-threat-intel-enricher  AbuseIPDB enrichment sidecar
fl-ui                     First Light web dashboard
fl-webhook-relay          Webhook relay

signoz                    SigNoz query service (port 8080)
signoz-clickhouse         ClickHouse (logs + metrics storage)
signoz-otel-collector     OTel collector (syslog port 5140, scrapes metrics)
signoz-zookeeper-1        ZooKeeper (ClickHouse dependency)
```

---

## Checking Status

```bash
# All fl- containers
docker ps --filter "name=fl-"

# Specific service logs
docker logs -f fl-agent
docker logs -f fl-slack-bot
docker logs --tail 50 signoz-otel-collector

# OTel collector config validated?
docker logs signoz-otel-collector 2>&1 | grep -E "Everything is ready|error|fatal"

# SSH events flowing?
docker exec signoz-clickhouse clickhouse-client \
  --query "SELECT count() FROM signoz_logs.logs_v2 WHERE timestamp > now() - INTERVAL 5 MINUTE AND mapContains(attributes_string, 'ssh.event')"
```

---

## OTel Collector Notes

The SigNoz OTel collector uses OpAMP to sync config from the SigNoz server. When you restart the container it fetches the latest config from `/var/tmp/collector-config.yaml`. If your local `signoz/otel-collector-config.yaml` changes don't seem to take effect, it may be because OpAMP has pushed a newer version. Check:

```bash
docker logs signoz-otel-collector 2>&1 | grep -E "Config has|reload"
```

**OTTL version constraints (v0.142.0):**
- Use `log.body` and `log.attributes["x"]` (not `body` / `attributes["x"]`)
- `IsPresent()` is **not available** in this build — use `IsMatch(log.body, "pattern")` guards instead
- `attributes["x"] == nil` throws `StandardPMapGetter` type errors — always use `IsMatch` guards
- Keep `error_mode: ignore` on transform processors; use `error_mode: propagate` only temporarily for debugging

---

## Pushing Langfuse Prompts

Domain agent prompts are managed in Langfuse. To push updates:

```bash
# LOCAL — run from repo root
cd /Users/tbailey/Dev/first-light
python3 scripts/push_all_prompts.py
```

Do **not** run this via docker exec or on the remote host — the `langfuse` package is only installed in the local venv.

---

## Branch Strategy

Active development is on `feature/langgraph-redesign`. When ready to merge:

```bash
git checkout main
git merge feature/langgraph-redesign
git push origin main
ssh tbailey@192.168.2.106 "cd /opt/first-light && git checkout main && git pull"
```

---

## Troubleshooting

**OTel collector not starting:**
```bash
docker logs signoz-otel-collector 2>&1 | grep -E "fatal|error|invalid"
```
Most common cause: OTTL syntax error in `otel-collector-config.yaml`. The collector logs the full error and rolls back to the previous working config.

**fl-agent unhealthy:**
```bash
docker logs fl-agent | tail -50
```
Check for: missing `.env` variables, Redis unreachable, ClickHouse connection failure.

**Slack bot not responding:**
```bash
docker logs fl-slack-bot | tail -30
```
Check for: `SLACK_BOT_TOKEN` / `SLACK_SIGNING_SECRET` in `.env`, Socket Mode enabled in Slack app settings.

**No metrics in ClickHouse:**
```bash
docker exec signoz-clickhouse clickhouse-client \
  --query "SELECT metric_name, count() FROM signoz_metrics.samples_v4 WHERE unix_milli > (toUnixTimestamp(now())-300)*1000 GROUP BY metric_name ORDER BY count() DESC LIMIT 10"
```
