# First Light — Master Punchlist

**Last Updated:** 2026-04-06
**Sources:** Code review (Apr 4), SYSTEM_AUDIT_MEGA_SECURE (Mar 4), LOG_PARSING_AUDIT (Mar 7), AGENT_IMPROVEMENT_PLAN (Apr 3), EPIC_FL_001 (Mar 28), daily report review (Apr 4), session review (Apr 5)

---

## 🔴 Critical — Fix Before Next Production Run

### ~~CR-1: SQL injection in `query_clickhouse_raw` allowlist check~~ ✅ FIXED
**Commit:** `9c3b2fd` — Replaced substring match with `_TABLE_RE` regex extraction of actual FROM/JOIN table references verified against the allowlist.

### ~~CR-2: ClickHouse password leaked in URL query params~~ ✅ FIXED
**Commit:** `9c3b2fd` — Credentials moved to `X-ClickHouse-User` / `X-ClickHouse-Key` headers in both `logs.py` and `metrics.py`.

### ~~CR-3: PBS TLS verification unconditionally disabled~~ ✅ FIXED
**Commit:** `9c3b2fd` — `pbs_verify_ssl` config field added; `_pbs_get()` now honours it.

### ~~CR-4: Domain agents run serially despite `Send` fan-out~~ ✅ FIXED
**Commit:** `555d64c` — Replaced LangGraph `Send` fan-out with `ThreadPoolExecutor`; all 7 domain agents now run concurrently (~1 min vs ~5 min).

### ~~CR-5: Double `.format()` on Langfuse prompts — KeyError on curly braces~~ ✅ FIXED
**Commit:** `9c3b2fd` — Replaced `.format(hours=hours)` with `.replace("{hours}", str(hours))` in all 7 domain agents.

---

## 🟠 Important — Address Soon

### ~~CR-6: QNAP baseline regex captures wrong percentage~~ ✅ FIXED
**Commit:** `99b78c8` — Regex anchored to QNAP-specific context line before extracting percentage.

### ~~CR-7: Cloudflare zone analytics double-counts requests~~ ✅ FIXED
**Commit:** `99b78c8` — Added explicit `groupBy` to GraphQL aliases; `error_rate_pct` now accurate.

### ~~CR-8: QNAP session cache has TOCTOU race under concurrency~~ ✅ FIXED
**Commit:** `99b78c8` — `threading.Lock()` wraps `_qnap_get_sid` check-and-set.

### ~~AG-1: `query_ntopng_flows_by_host` — verify endpoint works~~ ✅ FIXED
**Commit:** `555d64c` — Community Edition doesn't support `host=` filter server-side. Fixed to fetch all flows and filter client-side by client.ip/server.ip.

### ~~AG-2: CrowdSec pfSense bouncer~~ ⛔ SKIPPED
CrowdSec is not an official pfSense package. Dropped.

### ~~AG-3: SSH/sudo log parser disabled~~ ✅ ALREADY ACTIVE
Stale finding from Mar 7 audit. Parser is live in the OTel pipeline at `otel-collector-config.yaml:601`.

### ~~CR-9: Fragile regex row-limit enforcement in raw query tool~~ ✅ FIXED
**Commit:** `99b78c8` — Replaced regex LIMIT substitution with strip-and-append; added server-side `max_result_rows` ClickHouse setting as hard backstop.

---

## 🟡 Enhancements — Backlog

### Data Gaps

**~~DG-1: UniFi Controller API tools~~** ✅ DONE — `query_unifi_clients`, `query_unifi_ap_stats`, `lookup_unifi_client_by_mac` in `agent/tools/unifi_tools.py`. Commit: `53c94f9`. Also fixed `query_wireless_health` to extract MACs from `STA_ASSOC_TRACKER` syslog events (commit `243b7a1`) — identified `d8:d5:b9:00:bb:9f` (Rainforest Automation smartmeter) as the source of 219 daily auth failures.

**~~DG-2: Per-client blocked domains tool~~** ✅ DONE — `query_adguard_per_client_blocked_domains` in `agent/tools/metrics.py`. Queries `adguard_client_top_blocked_domain_queries_24h` from ClickHouse. Wired into DNS domain agent and INTERACTIVE_TOOLS.

**DG-3: Validator block proposals and attestation delay** — Deferred. Requires `VALIDATOR_PUBKEYS` configured in `.env`.

**~~DG-4: AdGuard NXDomain rate per client~~** ✅ DONE — `query_adguard_client_new_domains` in `agent/tools/metrics.py`. Queries `adguard_client_new_domains_24h` (newly-seen domains per client — the available proxy for DGA/C2 rotation; exporter does not expose per-client NXDomain separately). Wired into DNS domain agent and INTERACTIVE_TOOLS.

**~~DG-5: QNAP directory sizes~~** ✅ DONE — `query_qnap_directory_sizes` implemented in `agent/tools/qnap_tools.py`.

### Agent Architecture

**~~AA-1: Async graph execution~~** ✅ DONE — see CR-4 above (`555d64c`).

**AA-2: Episodic memory across reports** (deferred post-V1)
Synthesis agent reads/writes facts to Redis across daily runs — repeat IPs, recurring failures, baselines beyond the 5 current metrics. ~3-5 story points.

**~~AA-3: Structured domain outputs~~** ✅ DONE — All 7 domain agents append `---JSON-OUTPUT---` + JSON block (overall_severity, findings list, metrics dict). Graph parses into `DomainResult.findings/metrics/overall_severity`. Phase A suspicious-item extraction now reads structured findings directly instead of LLM re-parse. `_extract_baseline_metrics` reads from metrics dicts with regex fallback. Commit: `433a947`.

**~~AA-4: Investigation agent threshold tuning~~** ✅ DONE — `agent/graphs/daily_report_graph.py` now always logs investigation item count (Phase A extraction) regardless of whether items were found. Commit: `5ad5cd9`.

### Agent Tools

**~~TOOL-3: Cloudflare DNS records reader~~** ✅ DONE — `query_cloudflare_dns_records` in `agent/tools/cloudflare_tools.py`. Commit: `eff2169`.

**~~TOOL-4: Cloudflare Access policies reader~~** ✅ DONE — `query_cloudflare_access_apps` in `agent/tools/cloudflare_tools.py`. Commit: `eff2169`.

**~~TOOL-7: CrowdSec metrics / hub status~~** ✅ DONE — `query_crowdsec_metrics` in `agent/tools/crowdsec.py`. Commit: `eff2169`.

**~~TOOL-8: Proxmox VM/CT config reader~~** ✅ DONE — `query_proxmox_vm_configs` in `agent/tools/proxmox_tools.py`. Commit: `eff2169`.

**~~TOOL-9: PBS prune/retention policy reader~~** ✅ DONE — `query_pbs_prune_policies` in `agent/tools/pbs.py`. Commit: `eff2169`.

**~~TOOL-12: Switch port config / VLAN membership~~** ✅ DONE — `query_switch_port_status` in `agent/tools/switch_tools.py`. Commit: `5ad5cd9`.

**~~TOOL-13: Validator client config reader~~** ✅ DONE — `query_validator_node_config` in `agent/tools/validator.py` (Nimbus beacon REST API). Commit: `5ad5cd9`.

**~~TOOL-14: Uptime Kuma monitor definitions reader~~** ✅ DONE — `query_uptime_kuma_monitors` in `agent/tools/uptime_kuma.py`. Commit: `5ad5cd9`.

**~~TOOL-16: SigNoz/ClickHouse log search by hostname~~** ✅ DONE — `search_logs_by_hostname` in `agent/tools/logs.py`. Commit: `5ad5cd9`.

**TOOL-1: pfSense firewall rules reader** — Dropped. XML-RPC requires admin group membership; replaced by DNS resolution tools.

**TOOL-2: pfSense DNS resolver host overrides** — Dropped. Same auth constraint as TOOL-1.

**~~TOOL-5: AdGuard custom rules / allowlist reader~~** — Dropped. Data covered by existing ClickHouse exporter tools.

**~~TOOL-6: AdGuard per-client query detail~~** — Dropped. Covered by DG-2 (`query_adguard_per_client_blocked_domains`) and DG-4 (`query_adguard_client_new_domains`).

**TOOL-10: UniFi Controller client list + AP stats** — Open (overlaps DG-1).

**TOOL-11: UniFi Controller site config reader** — Open (overlaps DG-1).

**~~DG-6: Switch syslog event tool~~** ✅ DONE — `query_switch_events` in `switch_tools.py`. Queries ClickHouse for port state changes, detects flapping (>2 changes/60min). Port 5 flapped 6+ times on 2026-04-05. Wired into infrastructure domain agent and INTERACTIVE_TOOLS.

**~~DG-7: Home Assistant domain agent~~** ✅ DONE — New 8th concurrent domain agent `run_home_automation_agent`. `ha_tools.py` with `query_ha_logbook`, `query_ha_entity_states`, `query_ha_entity_history`. REST API (not syslog — HA syslog is OS noise only). Wired into daily report graph and INTERACTIVE_TOOLS. HTTPS fixed, synthesis template updated.

**~~DG-8: Home Assistant metrics tool~~** ✅ DONE — `query_ha_metrics` in `ha_tools.py`. Queries `/api/states` REST API filtered to sensor/climate/binary_sensor/device_tracker domains. Returns numeric values (power W/kWh, temp °F/°C, humidity %), anomaly list for unavailable sensors. HA Prometheus integration not required. Wired into home_automation agent and INTERACTIVE_TOOLS.

**~~TOOL-15: ntopng host details by IP~~** — Dropped. `query_ntopng_host_details` and `query_ntopng_host_l7_stats` already exist in `ntopng.py`.

### Slack Interactive Bot

**~~SLK-1: `run_interactive_query()` in graph~~** ✅ DONE — `agent/graph.py`.

**~~SLK-2: Full Slack App (Socket Mode, slash commands, mentions, threads, buttons)~~** ✅ DONE — `bot/slack_bot.py`: `/firstlight` slash command, `@firstlight` mentions with threaded replies, `alert_investigate` / `alert_acknowledge` / `alert_snooze` action handlers. Commit: `018a94f`.

**~~SLK-3: Reports to `#firstlight-reports`; alerts to `#firstlight-alerts`~~** ✅ DONE — `SlackBotChannel` in `agent/notifications/slack.py` posts to configurable channels via `chat.postMessage`; alert messages include Block Kit action buttons. Commit: `018a94f`.

**~~SLK-4: Conversation history via Redis (thread_ts keyed, TTL 24h)~~** ✅ DONE — History keyed by `thread_ts` when in a thread, channel for DMs; TTL 24h. Commit: `018a94f`.

### Infrastructure / Security Actions (manual — from daily report findings)

**~~INF-1:~~** ✅ Removed public DNS records for `pve`, `portainer`, `pbs`
**~~INF-2:~~** ✅ Added Cloudflare Access to `ha.mcducklabs.com`
**~~INF-3:~~** ✅ Deleted `openmwebui.mcducklabs.com` CF DNS record (typo, stale)
**INF-4:** Add CF Access to `ntfy.mcducklabs.com` — **OPEN, needs review**
**~~INF-5:~~** ✅ Verified `blxrbdn.com` — confirmed bloXroute BDN MEV relay discovery, legitimate
**~~INF-6:~~** ✅ Nimbus restart investigated and resolved
**INF-7:** Check vm/115 — backup stale 23 days, re-enable or decommission — **OPEN**
**INF-8:** Verify CrowdSec is ingesting current logs (`cscli metrics`) — **OPEN**
**~~INF-9:~~** ✅ Added DNS name for camera at `192.168.3.15`
**~~INF-10:~~** ✅ Identified and fixed rejected Wi-Fi client on UnifiBasement
**INF-11:** Enforce key-only SSH on `adguard` and `openclaw` — **OPEN, needs review**

**INF-12: Disable GUI on krusty (VM 116, 192.168.4.5)** — Running Ubuntu Desktop in DMZ VLAN with high memory. Disable display manager and set multi-user boot target. Commands: `systemctl status display-manager` then `systemctl disable --now <dm> && systemctl set-default multi-user.target && reboot`. **USER action.**

**INF-13: Investigate pulse disk writes** — LXC 102, 1.60 MB/s sustained write observed in Proxmox Pulse. SSH in and run `iotop` or `lsof` to confirm it's normal metric storage, not a runaway process. **USER action.**

**INF-14: vm/115 backup** — Stale 23+ days, re-enable or decommission. Carried from INF-7. **USER action.**

**INF-15: Enable HA Prometheus integration** — Required for DG-8. Steps:
  1. HA → Settings → Integrations → search "Prometheus" → Install
  2. HA → Profile → Security → Long-Lived Access Tokens → Create → copy value
  3. Add to `.env` on remote: `HA_HOST=192.168.2.52` and `HA_TOKEN=<token>`
  4. Verify: `curl -H "Authorization: Bearer <token>" http://192.168.2.52:8123/api/prometheus`
  **Partially done: token added, HTTPS fixed. DG-8 implemented via REST API (no Prometheus integration needed).**

---

## Deferred (Explicitly Post-V1)

- **BookStack auto-documentation** — `scripts/generate_bookstack_docs.py` via BookStack API at bookstack.mcducklabs.com. Needs `BOOKSTACK_TOKEN_ID/SECRET` in `.env`.
- **MCP servers per data source** — expose tools to external LLMs
- **Agentic response actions** — block IPs on pfSense, quarantine devices to restricted VLAN
- **Home Assistant integration** — moved to active backlog as DG-7 (syslog) and DG-8 (Prometheus)
- **Weekly trend reports** — month-over-month comparison
