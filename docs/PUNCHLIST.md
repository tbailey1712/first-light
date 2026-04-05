# First Light — Master Punchlist

**Last Updated:** 2026-04-04 (post-sprint update — all sections through Enhancements complete)
**Sources:** Code review (Apr 4), SYSTEM_AUDIT_MEGA_SECURE (Mar 4), LOG_PARSING_AUDIT (Mar 7), AGENT_IMPROVEMENT_PLAN (Apr 3), EPIC_FL_001 (Mar 28), daily report review (Apr 4)

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

### AG-2: CrowdSec pfSense bouncer — needs pfSense package install
CrowdSec is ingesting pfSense logs and generating alerts (confirmed working). Bouncer key regenerated: `8VQkmEinsPzYR4eezow/51iF7wYg8Vxm4pxLQCNPbc8`
**Action needed (manual — pfSense UI):**
1. pfSense → System → Package Manager → install `crowdsec`
2. Services → CrowdSec → LAPI URL: `http://192.168.2.106:8080`, API Key: above
3. Save — pfSense will start enforcing CrowdSec bans at firewall level

### ~~AG-3: SSH/sudo log parser disabled~~ ✅ ALREADY ACTIVE
Stale finding from Mar 7 audit. Parser is live in the OTel pipeline at `otel-collector-config.yaml:601`.

### ~~CR-9: Fragile regex row-limit enforcement in raw query tool~~ ✅ FIXED
**Commit:** `99b78c8` — Replaced regex LIMIT substitution with strip-and-append; added server-side `max_result_rows` ClickHouse setting as hard backstop.

---

## 🟡 Enhancements — Backlog

### Data Gaps

**~~DG-1: UniFi Controller API tools~~** ✅ DONE — `query_unifi_clients`, `query_unifi_ap_stats`, `lookup_unifi_client_by_mac` in `agent/tools/unifi_tools.py`. Commit: `53c94f9`. Also fixed `query_wireless_health` to extract MACs from `STA_ASSOC_TRACKER` syslog events (commit `243b7a1`) — identified `d8:d5:b9:00:bb:9f` (Rainforest Automation smartmeter) as the source of 219 daily auth failures.

**DG-2: Per-client blocked domains tool** ⏳ PENDING — Spec written and handed off to AdGuard analytics agent. Requires adding `export_per_client_blocked_domains()` to `/home/tbailey/adgh/adguard_metrics_exporter_v2.py` on the AdGuard LXC. Once deployed, add `query_adguard_per_client_blocked_domains` to `agent/tools/metrics.py`.

**DG-3: Validator block proposals and attestation delay** — Deferred. Requires `VALIDATOR_PUBKEYS` configured in `.env`.

**DG-4: AdGuard NXDomain rate per client** (was DATA-5)
NXDomain spikes per client are a reliable DGA/C2 signal. Current tools don't surface this.

**~~DG-5: QNAP directory sizes~~** ✅ DONE — `query_qnap_directory_sizes` implemented in `agent/tools/qnap_tools.py`.

### Agent Architecture

**~~AA-1: Async graph execution~~** ✅ DONE — see CR-4 above (`555d64c`).

**AA-2: Episodic memory across reports** (deferred post-V1)
Synthesis agent reads/writes facts to Redis across daily runs — repeat IPs, recurring failures, baselines beyond the 5 current metrics. ~3-5 story points.

**AA-3: Structured domain outputs**
Domain agents return free-text markdown. Synthesis has to re-parse it. If domains returned JSON schema (severity, findings list, metrics dict), synthesis quality and investigation triggering would improve.

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

**TOOL-5: AdGuard custom rules / allowlist reader** — Open. No direct API needed currently; data available via ClickHouse exporter.

**TOOL-6: AdGuard per-client query detail** — Open (overlaps DG-2).

**TOOL-10: UniFi Controller client list + AP stats** — Open (overlaps DG-1).

**TOOL-11: UniFi Controller site config reader** — Open (overlaps DG-1).

**TOOL-15: ntopng host details by IP** — Open.

### Slack Interactive Bot

**~~SLK-1: `run_interactive_query()` in graph~~** ✅ DONE — `agent/graph.py`.

**~~SLK-2: Full Slack App (Socket Mode, slash commands, mentions, threads, buttons)~~** ✅ DONE — `bot/slack_bot.py`: `/firstlight` slash command, `@firstlight` mentions with threaded replies, `alert_investigate` / `alert_acknowledge` / `alert_snooze` action handlers. Commit: `018a94f`.

**~~SLK-3: Reports to `#firstlight-reports`; alerts to `#firstlight-alerts`~~** ✅ DONE — `SlackBotChannel` in `agent/notifications/slack.py` posts to configurable channels via `chat.postMessage`; alert messages include Block Kit action buttons. Commit: `018a94f`.

**~~SLK-4: Conversation history via Redis (thread_ts keyed, TTL 24h)~~** ✅ DONE — History keyed by `thread_ts` when in a thread, channel for DMs; TTL 24h. Commit: `018a94f`.

### Infrastructure / Security Actions (manual — from daily report findings)

**INF-1:** Remove public DNS records for `pve`, `portainer`, `pbs` — actively enumerated
**INF-2:** Add Cloudflare Access to `ha.mcducklabs.com`
**INF-3:** Audit and delete `openmwebui.mcducklabs.com` CF DNS record (typo, stale)
**INF-4:** Add CF Access to `ntfy.mcducklabs.com`
**INF-5:** Verify `blxrbdn.com` (bloXroute BDN) is intentionally configured on validator
**INF-6:** Investigate why Nimbus restarted ~2h before today's report
**INF-7:** Check vm/115 — backup stale 23 days, re-enable or decommission
**INF-8:** Verify CrowdSec is ingesting current logs (`cscli metrics`)
**INF-9:** Add DNS name for camera at `192.168.3.15`
**INF-10:** Identify and fix rejected Wi-Fi client on UnifiBasement (156 auth failures)
**INF-11:** Enforce key-only SSH on `adguard` and `openclaw`

---

## Deferred (Explicitly Post-V1)

- **BookStack auto-documentation** — `scripts/generate_bookstack_docs.py` via BookStack API at bookstack.mcducklabs.com. Needs `BOOKSTACK_TOKEN_ID/SECRET` in `.env`.
- **MCP servers per data source** — expose tools to external LLMs
- **Agentic response actions** — block IPs on pfSense, quarantine devices to restricted VLAN
- **Home Assistant integration** — correlate network events with physical events
- **Weekly trend reports** — month-over-month comparison
