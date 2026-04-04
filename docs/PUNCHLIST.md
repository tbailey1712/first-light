# First Light — Master Punchlist

**Last Updated:** 2026-04-04 (Telegram deprecated — Slack is primary UI)
**Sources:** Code review (Apr 4), SYSTEM_AUDIT_MEGA_SECURE (Mar 4), LOG_PARSING_AUDIT (Mar 7), AGENT_IMPROVEMENT_PLAN (Apr 3), EPIC_FL_001 (Mar 28), daily report review (Apr 4)

---

## 🔴 Critical — Fix Before Next Production Run

### CR-1: SQL injection in `query_clickhouse_raw` allowlist check
**File:** `agent/tools/investigation.py:42-45`
The table allowlist is a substring match on the full SQL string. A query like `SELECT * FROM system.tables WHERE name = 'signoz_logs.logs_v2'` passes the check. Fix: extract actual FROM/JOIN table references via regex and verify those against the allowlist.

```python
_TABLE_RE = re.compile(r'\bFROM\s+([\w.]+)|\bJOIN\s+([\w.]+)', re.IGNORECASE)
referenced = {m.group(1) or m.group(2) for m in _TABLE_RE.finditer(sql)}
if not referenced.issubset({t.upper() for t in _ALLOWED_TABLES}):
    return json.dumps({"error": f"Query must only target: {', '.join(_ALLOWED_TABLES)}"})
```

### CR-2: ClickHouse password leaked in URL query params
**Files:** `agent/tools/logs.py:617`, `agent/tools/metrics.py:479`
Password passed as `?password=...` URL param — appears in server access logs and proxy logs. Use `X-ClickHouse-User` / `X-ClickHouse-Key` headers instead.

### CR-3: PBS TLS verification unconditionally disabled
**File:** `agent/tools/pbs.py:44`
`verify=False` hardcoded with no config toggle. Add `pbs_verify_ssl: bool = False` to config (same pattern as `proxmox_verify_ssl`) to make intent explicit.

### CR-5: Double `.format()` on Langfuse prompts — KeyError on curly braces
**File:** `agent/domains/daily_report.py:53` (and all domain agents)
`get_prompt()` in `initialize()` already compiles `{hours}`, then each domain agent calls `.format(hours=hours)` again on the compiled string. Any future prompt edit using JSON examples or Langfuse `{{variable}}` syntax will crash the domain agent silently. Fix: use `prompt.replace("{hours}", str(hours))` in domain agents, or ensure `get_prompt()` is not called with `hours=` in `initialize()`.

---

## 🟠 Important — Address Soon

### CR-4: Domain agents run serially despite `Send` fan-out
**File:** `agent/graphs/daily_report_graph.py:640,683`
Graph is compiled and invoked synchronously. LangGraph `Send` fan-out only parallelises under async execution. All 7 domain agents run one after another (~5 min each). Switch to `async` nodes + `await graph.ainvoke()` to get true parallel execution and cut report time by ~6×.

### CR-6: QNAP baseline regex captures wrong percentage
**File:** `agent/graphs/daily_report_graph.py:544`
`re.search(r'(\d+\.?\d*)\s*%\s*(?:used|full|capacity)', infra)` captures the first percentage in the infra summary — could be Proxmox RAM, PBS storage, or Frigate before reaching QNAP. Anchor the regex to a QNAP-specific context line.

### CR-7: Cloudflare zone analytics double-counts requests
**File:** `agent/tools/cloudflare_tools.py:354-381`
GraphQL aliases `byStatus` and `byCountry` both return rows grouped by all dimensions. Status count aggregation double-counts requests, making `error_rate_pct` smaller than actual. Fix the GraphQL query to use separate dimension groups.

### CR-8: QNAP session cache has TOCTOU race under concurrency
**File:** `agent/tools/qnap_tools.py:22-23`
Module-level `_qnap_sid` / `_qnap_sid_expiry` with no threading lock. Not a live issue while graph runs serially (CR-4), but will become a race condition when async parallelism is added. Add `threading.Lock()` around `_qnap_get_sid`.

### CR-9: Fragile regex row-limit enforcement in raw query tool
**File:** `agent/tools/investigation.py:52`
Regex-based LIMIT replacement is bypassable with subquery LIMIT clauses or SQL comments. Acceptable risk for now but should be replaced with proper SQL parsing or a ClickHouse-level `max_result_rows` setting in the HTTP request params.

### AG-1: ~~`query_ntopng_flows_by_host` — verify endpoint works~~ ✅ FIXED
Community Edition doesn't support `host=` filter server-side. Fixed to fetch all flows and filter client-side by client.ip/server.ip.

### AG-2: CrowdSec pfSense bouncer — needs pfSense package install
CrowdSec is ingesting pfSense logs and generating alerts (confirmed working). Bouncer key regenerated: `8VQkmEinsPzYR4eezow/51iF7wYg8Vxm4pxLQCNPbc8`
**Action needed (manual — pfSense UI):**
1. pfSense → System → Package Manager → install `crowdsec`
2. Services → CrowdSec → LAPI URL: `http://192.168.2.106:8080`, API Key: above
3. Save — pfSense will start enforcing CrowdSec bans at firewall level

### AG-3: ~~SSH/sudo log parser disabled~~ ✅ ALREADY ACTIVE
Stale finding from Mar 7 audit. Parser is live in the OTel pipeline at `otel-collector-config.yaml:601`.

---

## 🟡 Enhancements — Backlog

### Data Gaps

**DG-1: UniFi Controller API tools** (was DATA-4 in improvement plan)
Wireless domain currently only uses syslog (`query_wireless_health`). UniFi Controller has a full REST API for client list, AP stats, roaming history, RF environment. High leverage for the wireless agent.

**DG-2: Per-client blocked domains tool** (was DATA-1)
AdGuard can return top blocked domains per client IP. Needed for the DNS agent to investigate high-risk clients like `bookstack` (100% block rate flagged in today's report).

**DG-3: Validator block proposals and attestation delay** (was DATA-3)
`query_validator_health` returns balance and peer count but not attestation inclusion delay or block proposal history. Add beacon API calls for these.

**DG-4: AdGuard NXDomain rate per client** (was DATA-5)
NXDomain spikes per client are a reliable DGA/C2 signal. Current tools don't surface this.

**DG-5: QNAP directory sizes** (was DATA-8 / S2-05)
Auto-trigger cleanup recommendation when a volume is near-full. `query_qnap_directory_sizes` tool needed.

### Agent Architecture

**AA-1: Async graph execution** (see CR-4 above — classify as enhancement once critical fix tracked separately)

**AA-2: Episodic memory across reports** (deferred post-V1)
Synthesis agent reads/writes facts to Redis across daily runs — repeat IPs, recurring failures, baselines beyond the 5 current metrics. ~3-5 story points.

**AA-3: Structured domain outputs**
Domain agents return free-text markdown. Synthesis has to re-parse it. If domains returned JSON schema (severity, findings list, metrics dict), synthesis quality and investigation triggering would improve.

**AA-4: Investigation agent threshold tuning**
Today's report had 0 suspicious items trigger the investigation node. Need to verify the Phase A structured extraction is producing items and the threshold is calibrated correctly. Add logging for extracted item count.

### Infrastructure / Security Actions (from today's report)

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

### Slack Interactive Bot (replaces Telegram — deprecated)

Slack is the primary chat UI. `fl-slack-bot` currently sends reports via webhook only (one-way). Needs to become a full Slack app with two-way interaction.

**SLK-1:** `run_interactive_query()` in graph — single-turn Q&A entry point accepting a question + optional context, returns markdown
**SLK-2:** Upgrade `fl-slack-bot` to a Slack App (Socket Mode or Events API) supporting:
  - Slash commands: `/fl-status`, `/fl-ask <question>`, `/fl-digest`, `/fl-alerts`
  - `@firstlight <question>` app mentions routed to the agent
  - Threaded replies for follow-up questions (Redis conversation state keyed by thread_ts)
  - Interactive buttons on alert messages (e.g. "Investigate", "Acknowledge", "Snooze")
**SLK-3:** Daily report posted to a dedicated `#firstlight-reports` channel; alerts to `#firstlight-alerts`
**SLK-4:** Conversation history via Redis (thread_ts → message history, TTL 24h)

---

## Agent Tool Opportunities

Goal: agents should be able to independently verify findings, look at configs, and make actionable recommendations — not just report what the data shows. Many issues flagged in daily reports may already be addressed; tools should let the agent check before calling something out.

### Config & State Verification Tools (high value)

**TOOL-1: pfSense firewall rules reader** (XML-RPC)
Read current NAT rules, firewall rules, and aliases. Lets the agent verify that a redirect rule exists before flagging "device bypassing NTP" — or confirm that a rule was removed.

**TOOL-2: pfSense DNS resolver host overrides** (XML-RPC)
Read Unbound host overrides and domain overrides. Agent can verify DNS entries exist for flagged IPs instead of just recommending them.

**TOOL-3: Cloudflare DNS records reader** (already have CF token)
List all DNS records for mcducklabs.com. Agent can verify whether `pve`, `portainer`, `pbs` actually have public records before flagging them, and auto-suggest deletion.

**TOOL-4: Cloudflare Access policies reader**
List CF Access applications and which hostnames are protected. Agent can verify `ha.mcducklabs.com` lacks Access before flagging it — and stop flagging it once it's added.

**TOOL-5: AdGuard custom rules / allowlist reader**
Read current AdGuard filtering rules. Agent can verify whether a domain is already blocked or allowed before recommending action.

**TOOL-6: AdGuard per-client query detail**
Query AdGuard for all blocked domains for a specific client in the past N hours. Critical for investigating `bookstack` (100% block rate) and other high-risk clients.

**TOOL-7: CrowdSec metrics / hub status** (SSH or API)
`cscli metrics` output — verifies CrowdSec is ingesting logs. `cscli hub list` — verifies which scenarios/collections are installed. Lets agent confirm whether CrowdSec is healthy before flagging it as inactive.

**TOOL-8: Proxmox VM/CT config reader**
Read VM/CT configuration (disk size, CPU, RAM allocation, backup schedule) from Proxmox API. Lets agent verify vm/115 backup schedule, check HA VM disk allocation, confirm which VMs exist before flagging stale backups.

**TOOL-9: PBS prune/retention policy reader**
Read PBS datastore prune settings. Agent can confirm whether a stale backup group is intentionally excluded vs. a real failure.

**TOOL-10: UniFi Controller client list + AP stats** (REST API)
Full client inventory with MAC, AP association, RSSI, auth status. Lets agent identify the rejected Wi-Fi client (156 auth failures) by MAC rather than just flagging it.

**TOOL-11: UniFi Controller site config reader**
Read WLAN configs, security settings. Agent can verify whether WPA3, 802.1X, or RADIUS is configured.

**TOOL-12: Switch port config / VLAN membership** (SNMP or REST)
Read per-port VLAN assignments and STP state. Lets agent verify VLAN isolation claims before making cross-VLAN traffic allegations.

**TOOL-13: Validator client config reader** (SSH to validator host or config API)
Read Nimbus/Nethermind config files to verify whether bloXroute BDN is configured, fee recipient, graffiti, MEV relay endpoints. Resolves recurring `blxrbdn.com` DNS flag without operator intervention.

**TOOL-14: Uptime Kuma monitor definitions reader**
List all configured monitors with URLs and check intervals. Agent can correlate a failing monitor against what it's actually checking.

**TOOL-15: ntopng host details by IP**
Deep per-host data: full flow history, protocol breakdown, all alerts for a specific IP. Complements `query_ntopng_flows_by_host` for investigation.

**TOOL-16: SigNoz/ClickHouse log search by hostname**
Direct lookup: "show me all logs from host X in the past N hours" — useful for investigating a specific device flagged in the report without a raw SQL query.

---

## Deferred (Explicitly Post-V1)

- **BookStack auto-documentation** — `scripts/generate_bookstack_docs.py` via BookStack API at bookstack.mcducklabs.com. Needs `BOOKSTACK_TOKEN_ID/SECRET` in `.env`.
- **MCP servers per data source** — expose tools to external LLMs
- **Agentic response actions** — block IPs on pfSense, quarantine devices to restricted VLAN
- **Home Assistant integration** — correlate network events with physical events
- **Weekly trend reports** — month-over-month comparison
