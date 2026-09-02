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

**~~DG-9: Per-device bandwidth anomaly detection~~** ✅ DONE — `query_device_bandwidth_anomalies` in `agent/tools/ntopng.py`. Diffs ntopng cumulative bytes against Redis 7-day rolling baseline (fl:bw:snap/{ip}, fl:bw:hist/{ip}). Flags devices >2.5× average AND >100 MB. Handles ntopng counter resets. Wired into network_flow agent and INTERACTIVE_TOOLS. First report will record snapshots; anomaly detection fires from run 2 onward.

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
**~~INF-4:~~** ✅ Migrated ntfy → Pushover. `PushoverChannel` in `agent/notifications/pushover.py`. Registry updated. Remote `.env` has `PUSHOVER_TOKEN=` and `PUSHOVER_USER_KEY=` placeholders — fill in from pushover.net dashboard + app token to activate.
**~~INF-5:~~** ✅ Verified `blxrbdn.com` — confirmed bloXroute BDN MEV relay discovery, legitimate
**~~INF-6:~~** ✅ Nimbus restart investigated and resolved
**~~INF-7:~~** ✅ vm/115 decommissioned.
**~~INF-8:~~** ✅ CrowdSec healthy — acquis.d/first-light.yml correctly watches `/var/log/remote/*/syslog.log`. pfSense blocks perimeter attacks before they reach internal hosts, so no SSH brute force reaches internal syslogs. nginx parser active (89K/92K parsed). No decisions = pfSense is doing its job, not a CrowdSec failure.
**~~INF-9:~~** ✅ Added DNS name for camera at `192.168.3.15`
**~~INF-10:~~** ✅ Identified and fixed rejected Wi-Fi client on UnifiBasement
**~~INF-11:~~** ✅ Closed — low risk, pfSense blocks external SSH, internal access only.

**~~INF-12:~~** ✅ GDM disabled on krusty, set to multi-user boot target. 3GB returned to PVE host pool.

**~~INF-13:~~** ✅ Pulse service stopped and disabled. Root cause: SQLite metrics.db WAL writes on every polling cycle. First Light covers all Pulse functionality. LXC 102 remains in place but onboot disabled.

**~~INF-14:~~** ✅ Closed with INF-7.

**INF-15: Enable HA Prometheus integration** — Required for DG-8. Steps:
  1. HA → Settings → Integrations → search "Prometheus" → Install
  2. HA → Profile → Security → Long-Lived Access Tokens → Create → copy value
  3. Add to `.env` on remote: `HA_HOST=192.168.2.52` and `HA_TOKEN=<token>`
  4. Verify: `curl -H "Authorization: Bearer <token>" http://192.168.2.52:8123/api/prometheus`
  **Partially done: token added, HTTPS fixed. DG-8 implemented via REST API (no Prometheus integration needed).**

---

## 👁️ Watch Items — Confirm Before Closing

### ~~WATCH-1: Log ingestion volume above baseline~~ ✅ RESOLVED 2026-09-02
**Answer: not backlog flush, and not `systemd-resolved`.** Re-measured 16h after the
collector restart. Per-day counts from `logs_v2`:

| Day | Rows | Note |
|---|---|---|
| 2026-08-11 … 08-18 | ~2.33M/day | true pre-outage steady state |
| 2026-08-19 | 10.82M | spike; same day all 8 domain agents failed |
| 2026-09-02 | ~5.0M/day projected | current |

Two corrections fell out of this:

1. **CLAUDE.md's "~850k logs/day" was stale.** The real pre-outage baseline was
   ~2.3M/day, so the increase is ~2.2x, not the ~5x first suspected.
2. **`systemd-resolved` was not the driver** — it is flat (1.06x vs Aug 18). The real
   growth is UniFi AP `mcad: wireless_agg_stats.log_sta_anomalies` per-station
   telemetry (19–43x across three APs), plus volume inflated by WATCH-2 below.

Remaining genuine reduction opportunity is the UniFi `mcad` stats chatter, which is
per-station telemetry with little security value. Not urgent: disk is at 49% and
ClickHouse is 6.2 GiB after the 2026-09-01 trim.

---

### ~~WATCH-2: `service.name` misattributed on ~31% of syslog records~~ ✅ FIXED 2026-09-02
**Opened:** 2026-09-02
**Impact: firewall data loss.** Of records whose *body* contains `filterlog[`, only
8,717 of 12,620 in a 30-minute sample carried `service.name=filterlog`. The other
**3,903 (31%)** were labelled `systemd-resolved`, the three UniFi APs, `nginx`,
`concord232_server`, `pulse-agent`, or `CEF`.

Because the pfSense CSV parsing in `signoz/otel-collector-config.yaml` (lines
133–143) is gated on `resource.attributes["service.name"] == "filterlog"`, those
3,903 records get **no `pfsense.*` attributes at all** — no src_ip, dst_ip, action,
interface or port. They are invisible to every structured `firewall_threat` query and
simultaneously pollute the wireless and DNS domains with foreign records.

Treat block counts in reports before this is fixed as undercounts of roughly a third.

**Root cause** — `otel-collector-config.yaml` line 80:
```yaml
- set(resource.attributes["service.name"], attributes["appname"]) where attributes["appname"] != nil
```
This sets a **resource** attribute from a **log-record** attribute inside a
`context: log` block. In the OTel data model many log records share a single Resource
object, so every record in a batch mutates the *same* resource and the last one
processed wins for all of them. Line 79 does the same to `host.name`.

**Fix:** add the `groupbyattrs` processor (not currently in the config) keyed on
`appname`/`hostname` *before* the transform, so each distinct combination gets its own
Resource and the `set()` becomes safe. Alternative: keep `service.name` as a log
attribute rather than promoting it to the resource, and re-gate the pfSense parsing on
`attributes["appname"]`.

**Fixed** in commit `ec57acd`: `groupbyattrs/syslog` splits the shared Resource by
`(appname, hostname)`, then `transform/promote_source` renames to `service.name` /
`host.name` in `context: resource`. Verified after the reload, filtering on
`observed_timestamp` (ingestion time) because clock-skewed hosts put pre-fix rows
inside a recent event-time window:

| Measure | Before | After |
|---|---|---|
| filterlog rows correctly tagged | 8,717 / 12,620 (69%) | **1,339 / 1,339 (100%)** |
| filterlog rows with `pfsense.*` fields | ~69% | **806 / 806 (100%)** |
| `systemd-resolved` rows carrying filterlog bodies | 1,725 | **0** |

⚠️ Any per-source log volume analysis dated before 2026-09-02 is unreliable. The
"AdGuardHome up 61x" figure in WATCH-1 was this bug — those rows were
`concord232_server`, `canonical-livepatch` and `systemd-timesyncd` from `krusty`.

---

### WATCH-3: Network-wide DNS timeouts since 2026-08-19 — ROOT-CAUSED 2026-09-02 🔴 ONGOING
**Opened:** 2026-09-02
**This is why log volume is up, and it is a live incident, not noise.**

`[STA_TRACKER] DNS request timed out` from the UniFi APs, per day:

| Day | STA_TRACKER DNS timeouts | `anomalies=dns_timeout` |
|---|---|---|
| Aug 13–18 | 1,800 – 4,600 | 1,000 – 2,200 |
| **Aug 19** | **1,157,164** | **181,936** |
| Aug 20 | 405,770 | 118,956 |
| Aug 21 (partial) | 119,302 | 33,383 |
| Aug 22–30 | *ingestion outage — no data* | |
| Sep 1 (partial) | 157,132 | 42,939 |
| Sep 2 | 194,319 and climbing | 49,499 |

A 50–100x step change beginning 2026-08-19 that has never come back down. It is
still running. Note 2026-08-19 is also the day all 8 domain agents failed on model
router 503s and daily log volume hit 10.8M — worth checking whether the DNS problem
caused that, rather than the two being coincidental.

Corroborating signals, all consistent with DNS resolution failing network-wide:
- `openwebui` (192.168.2.15) TXT query ratio 48.28 — flagged critical in the 09-02 report
- DNS block rate 24.7% against an 8% baseline
- `systemd-timesyncd: Timed out waiting for reply ... (ntp.ubuntu.com)` on `krusty`
- `canonical-livepatch ... POST request failed` on `krusty`

**Deliberately NOT filtered.** Dropping these at the collector was on the table as a
log-volume reduction, but they are the clearest signal of an unresolved incident and
suppressing them would hide it. Volume should fall back toward the ~2.3M/day baseline
on its own once DNS is fixed — re-measure then, and only add filters if it does not.

## Root cause: the AdGuard host is resource-starved

`192.168.1.3` (AdGuard Home + DHCP, per `docs/dhcp_leases.md:127`) cannot service DNS
under concurrency, so it **silently drops** queries. Clients see a timeout and retry,
which adds load and sustains the condition — a self-reinforcing loop, which is why it
has never recovered on its own.

Measured on the host 2026-09-02:

| Metric | Value | Notes |
|---|---|---|
| RAM | 2048 MB total, **16 MB free** | |
| Swap | **378 MB of 512 MB in use**, actively paging | `si` 188–196 |
| Run queue (`r`) | **4–16** on 4 vCPUs | sustained oversubscription |
| **CPU steal (`st`)** | **26–37% sustained** (one 64% sample) | hypervisor starvation |
| Load average | 12.35 / 9.50 / 7.75 | |

Reproduced live, from two source IPs on different VLANs:

| Test | Source | Result |
|---|---|---|
| Paced ~7 qps | docker host (VLAN 2) | 39/40 ok — 2.5% loss |
| 40 parallel | docker host (VLAN 2) | 12/40 ok — **70% loss** |
| Paced ~7 qps | AdGuard's own host | 30/30 ok — 0% loss |
| 40 parallel | AdGuard's own host | 19/40 ok — **53% loss** |
| Rate sweep | docker host | clean to 20 qps, degrades at 30 |

**Ruled out:**
- *Network path / pfSense / VLAN routing* — drops reproduce from AdGuard's own host.
- *Upstream resolver failure* — guaranteed-uncached lookups resolve in ~110 ms.
- *A single rogue device* — 10+ stations jumped 100–500x at the same instant.
- *The HA mDNS conflict loop* — constant ~70k/hour on both sides of the onset.
- *AppArmor denials* — `rsyslogd` state files in LXC namespaces, unrelated to DNS.

**Main contributor:** the `adgh` analytics stack is co-located on the resolver —
`ingest_logs.py` runs hourly at ~31% CPU / 417 MB RSS (20% of total RAM) against a
**6.6 GB** `cache.db`, alongside 4 gunicorn workers, on a 2 GB host.

### Recommended fixes (infrastructure — not applied, needs your call)
1. **Raise the LXC memory allocation**, 2 GB → 4 GB. Cheapest, addresses the swapping.
2. **Investigate the 26–37% CPU steal on the Proxmox host** — the guest is only getting
   about two-thirds of its allotted CPU, which no in-guest tuning can fix.
3. **Move the `adgh` analytics stack off the DNS resolver.** A 6.6 GB SQLite analytics
   workload does not belong on critical network infrastructure.
4. Raising AdGuard's `ratelimit` would mask the symptom, not fix it. Do 1–3 first.

**Still unknown:** the precise trigger at **2026-08-19 08:12 UTC** (03:12 CDT). Reading
`/opt/AdGuardHome/AdGuardHome.yaml` and `data/querylog.json` needs sudo on 192.168.1.3,
which this session does not have. Candidates: `cache.db` crossing a size threshold, an
`adgh` change, or Proxmox contention starting. AdGuard itself has not restarted since
the 2026-08-21 host boot, so a service restart is not the trigger.

*(An earlier note here suggested the Aug 19 model-router 503 storm might share a cause.
No evidence links them — router 503s are HTTP status responses, not DNS failures.)*

---

### WATCH-4: HA host in a runaway mDNS rename loop — ~21/sec 🔴
**Opened:** 2026-09-02
**Host:** Home Assistant, 192.168.2.52 (VM 109, the largest guest at 10 GB / 95% mem)

`systemd-resolved` on the HA host detects an mDNS name conflict, renames itself,
re-announces, immediately conflicts again, and repeats — forever:

```
ha systemd-resolved: Detected conflict on ha1709530.local IN A 192.168.2.52
ha systemd-resolved: Hostname conflict, changing published hostname from 'haN' to 'haN+1'
```

The counter is the rename count: **ha254334 on 08-19 → ha1709530 on 09-02**, about
**1.45M renames in 14 days**, currently ~21/second (76,000/hour, 1.82M/day). Before
filtering this was **43% of all log volume on the network**.

**Cost beyond logs:** every rename is an mDNS multicast announcement. WiFi multicast
is transmitted at the lowest basic rate, so ~21/sec of it is a continuous tax on every
wireless client — plausibly a contributor to WATCH-3's DNS timeouts, though not its
root cause (WATCH-3 is AdGuard resource starvation, and this loop ran at a flat
~70k/hour on both sides of that onset).

**Likely cause:** an mDNS reflector/repeater echoing the host's own announcements back
to it, so it sees its own claim as a conflict. Check for a Bonjour/mDNS repeater on
the UniFi network settings or an avahi-reflector on pfSense — particularly one bridging
VLAN 1 and VLAN 2, since HA sits on VLAN 2 and announces `IN A 192.168.2.52`.

**Fix (on the HA host, not available to this session — no SSH):**
- Disable systemd-resolved's mDNS: `MulticastDNS=no` in `/etc/systemd/resolved.conf`.
  HA does its own zeroconf in Python and does not need systemd-resolved's.
- Or set a stable hostname and stop the `_workstation._tcp` registration.
- Then find and disable the reflector so it does not recur.

**Currently filtered** at the OTel collector so it stops costing 1.8M rows/day. The
condition is unchanged on the network — re-check with:
`docker logs fl-rsyslog` or temporarily remove the filter in
`signoz/otel-collector-config.yaml`.

---

---

## Deferred (Explicitly Post-V1)

- **Switch Port 5 link flaps** — backyard camera EoC path. Chronic physical-layer failure (sub-second bounce pairs, 68+ flaps/day). Needs: inspect coax/F-connectors at both ends, swap EoC adapter, check PoE injector under load. Causes surveillance gaps on 192.168.3.15.
- **BookStack auto-documentation** — `scripts/generate_bookstack_docs.py` via BookStack API at bookstack.mcducklabs.com. Needs `BOOKSTACK_TOKEN_ID/SECRET` in `.env`.
- **MCP servers per data source** — expose tools to external LLMs
- **Agentic response actions** — block IPs on pfSense, quarantine devices to restricted VLAN
- **Home Assistant integration** — moved to active backlog as DG-7 (syslog) and DG-8 (Prometheus)
- **Weekly trend reports** — month-over-month comparison
