# First Light Agent Improvement Plan

*Based on deep analysis of live trace `3e48cc0649a278e2371695ed60a42fa5` (2026-04-03)*

Three tracks run in parallel. Each ticket is self-contained — one PR per ticket.

---

## Track 1 — Agent Architecture

**Goal:** Fix structural problems that no amount of prompt tuning can fix.

---

### ARCH-1: Fix `{hours}` template substitution bug
**Priority:** P0 — affects every single prompt on every run
**Effort:** 30 min

The Langfuse prompts contain literal `{hours}` placeholders that arrive verbatim to the LLM because Langfuse uses `{{hours}}` double-brace syntax for template variables but the stored prompts use single-brace. The model compensates by inferring from the user message — but this breaks on non-24h runs (6h alert sweeps, 48h weekly context).

**Fix:** Compile at call time in each `run_*_agent` function before passing to `run_react_loop`:
```python
system = prompt_override.format(hours=hours)
```
Apply to: `run_firewall_threat_agent`, `run_dns_agent`, `run_network_flow_agent`, `run_infrastructure_agent`, `run_wireless_agent`, `run_validator_agent`.

The `SYNTHESIS_USER` template already uses `.format()` — pattern is established.

---

### ARCH-2: Add correlation pass node to LangGraph
**Priority:** P1 — highest architectural leverage
**Effort:** 3–4 days

Current graph: `initialize → [6 fan-out agents] → synthesize`
Proposed: `initialize → [6 fan-out agents] → correlate → synthesize`

The correlation node runs after all 6 domain agents complete. It:
1. Extracts suspicious IPs and device identifiers from all 6 summaries (LLM call or regex)
2. Runs targeted cross-domain lookups on those entities:
   - `search_logs_by_ip(ip)` for any IP flagged by DNS as high-risk
   - `lookup_ip_threat_intel(ip)` for IPs not yet enriched
   - `query_ntopng_host_details(ip)` for DHCP devices flagged by DNS
3. Appends correlation findings to the synthesis context

This removes the dependency on the synthesis LLM to "notice" that `192.168.1.110` appears in both DNS and infrastructure summaries. Today it works by luck of context; tomorrow it's a structured pass.

**New state field:** `correlation_findings: str` injected between domain results and synthesis.

---

### ARCH-3: Structured domain outputs (JSON schema)
**Priority:** P2 — enables ARCH-2 and future automation
**Effort:** 1 week

Domain agents currently return freeform markdown. Change them to return a structured dict:

```python
{
  "domain": "firewall_threat",
  "overall_severity": "info",   # critical | warning | info | ok
  "findings": [
    {
      "severity": "warning",
      "title": "28k port 9000 blocks to validator",
      "detail": "...",
      "ips": ["169.150.222.204"],
      "tags": ["validator", "p2p", "ethereum"],
      "action_required": false
    }
  ],
  "metrics": { "total_blocks": 28236, "unique_ips": 847 },
  "markdown_summary": "..."   # still generated for synthesis / Slack
}
```

The `markdown_summary` field feeds synthesis unchanged. The structured fields enable:
- Programmatic IP extraction for ARCH-2 correlation pass
- Slack/Telegram severity-gated alerts (only send if `overall_severity != "ok"`)
- Long-term storage of per-domain metrics for trend tracking

---

### ARCH-4: Redis baseline comparison (episodic memory MVP)
**Priority:** P2
**Effort:** 2 days

Store 6 values in Redis after each daily run (via synthesis node):
```
fl:baseline:dns_queries
fl:baseline:dns_block_rate
fl:baseline:validator_balance
fl:baseline:qnap_vol1_pct
fl:baseline:active_dhcp_count
fl:baseline:firewall_blocks
```

Read them at the start of each run in `initialize()` and inject into the synthesis prompt as a "yesterday's baseline" context block. Cost: ~100 tokens per run. Value: every report becomes comparative — "DNS queries up 23% vs yesterday" instead of "65k queries (no context)."

---

### ARCH-5: Token budget optimisation
**Priority:** P3
**Effort:** 1 day

**Wireless and validator** each use 2 LLM calls and ~2,000 tokens for domains that currently produce near-zero signal. Add `agent_type="lite"` mapped to a smaller/cheaper model (Haiku or Sonnet) for simple single-tool domains. Keep Opus 4.6 for firewall, DNS, network_flow, infrastructure, synthesis.

**network_flow** burns ~20k tokens per run paging through raw active flows speculatively. This is a prompt fix (see PROMPT-3) but the architectural lever is capping `perPage` to 10 at the tool level and removing the ability to page unless a specific host IP is passed.

---

## Track 2 — Updated Prompts

**Goal:** Rewrite all 7 Langfuse prompts with specific context, clear thresholds, and no false positive traps. All rewrites go to Langfuse via the push script.

---

### PROMPT-1: Firewall & Threat Intelligence
**Langfuse slug:** `first-light-firewall-threat`

**Current problems:**
- Flags 28k Ethereum P2P port 9000 inbound as CRITICAL every run
- No trigger for `lookup_ip_threat_intel` when score is low but count is very high
- No instruction to check which pfSense *interface* a block came from
- No instruction to check outbound blocks (internal → WAN blocked)
- `query_threat_intel_coverage` never called — enricher health invisible

**Key additions:**
```
Known-good — do NOT flag as attacks:
- 192.168.4.2 is the Ethereum validator. Port 9000 TCP/UDP is LibP2P peer
  discovery. Inbound blocks from internet IPs to 192.168.4.2:9000 are other
  validators attempting to peer. NORMAL. Report volume as INFO only.

lookup_ip_threat_intel: call for the top 3 IPs by block_count where
block_count > 1000, regardless of threat score. Also call for any IP
with score > 50 (max 5 total).

query_threat_intel_coverage: always call this first. If coverage < 50%,
note that the enricher may be down — threat scores are unreliable.

Outbound blocks: if query_security_summary shows blocks where src_ip is
192.168.x.x, flag these separately — an internal device trying to reach
a blocked destination is a different threat class than external scans.
```

---

### PROMPT-2: DNS Security
**Langfuse slug:** `first-light-dns`

**Current problems:**
- No instruction for investigating specific blocked domains on high-risk clients
- No C2 beaconing or DGA signal guidance
- No guest VLAN (192.168.10.x) monitoring instruction
- No instruction to flag clients that went silent (potential DoH bypass)
- DHCP fingerprinting guidance exists but no instruction to correlate with ntopng

**Key additions:**
```
Guest VLAN (192.168.10.x): note count of active guests and flag any guest
client exceeding 2,000 queries/day or querying non-CDN/streaming domains.

High-risk client investigation: for any client with risk_score >= 7 or
block_rate > 50%, call query_adguard_block_rates to get their full profile.
Note: the blocked *domain names* are not available via metrics — flag these
clients for manual AdGuard query log review by name.

DoH bypass signal: if a 192.168.2.x device that normally generates
hundreds of DNS queries drops to near-zero, it may have switched to
DNS-over-HTTPS, bypassing AdGuard entirely. Flag any IoT device with
<10 queries in 24h that had >100 queries in prior periods (use
query_adguard_top_clients with a longer window to compare).

C2 indicators in DNS:
- traffic_type = "automated" + block_rate > 30% on an IoT device = possible
  C2 call-home being blocked. Investigate domain profile.
- DHCP device querying > 20 unique domains = may be a general-purpose
  computer, not an IoT device — update your classification.
```

---

### PROMPT-3: Network Flow
**Langfuse slug:** `first-light-network-flow`

**Current problems:**
- Agent pages through raw active flows speculatively — wastes 2 of 12 iterations
- VLAN isolation rules are vague ("flag isolated VLAN activity") — needs specific IPs
- No Validator VLAN bandwidth context
- No switch port-to-device mapping — port numbers are meaningless
- ntopng ARP table never called

**Key additions:**
```
query_ntopng_active_flows(): ONLY call if you identified a specific suspicious
host or anomalous protocol in prior steps. Do NOT page speculatively.
If called, use perPage=10. Only request page 2 if page 1 shows ongoing
anomalous activity that requires further investigation.

VLAN isolation (deviation = CRITICAL):
- 192.168.3.x (Cameras): ONLY flows TO 192.168.2.7:554 (Frigate RTSP) and
  192.168.2.9:554 (NAS RTSP). Any other destination = CRITICAL.
- 192.168.4.x (Validator DMZ): outbound to internet only. Any flow FROM
  192.168.4.x TO 192.168.1.x or 192.168.2.x = CRITICAL.
  Inbound to 192.168.4.2:9000 from internet = NORMAL validator P2P.

Validator VLAN bandwidth: report total bytes_in and bytes_out for
192.168.4.x from query_ntopng_vlan_traffic. Normal: 2–10 Mbps sustained
outbound. Flag if outbound > 20 Mbps sustained (possible compromise).

query_ntopng_arp_table(): call every run. Flag any IP-to-MAC mapping
where the MAC vendor is unexpected for that VLAN (e.g., a server NIC
vendor on VLAN 3 camera subnet would be suspicious).
```

---

### PROMPT-4: Infrastructure Health
**Langfuse slug:** `first-light-infrastructure`

**Current problems:**
- No instruction to drill down on full volumes (`query_qnap_directory_sizes`)
- No WAN link capacity — agent can't determine if bandwidth is "high"
- PBS results show vm/100 but agent has no VM name → id mapping
- No QNAP temperature thresholds defined
- Proxmox memory at 81% noted as "acceptable" with no trend context

**Key additions:**
```
REQUIRED: if query_qnap_health() shows any volume at >85% utilisation,
call query_qnap_directory_sizes(path="/share/CACHEDEV1_DATA") immediately.
Report the top 5 directories by size. Do not skip this step.

WAN link is 500/500 Mbps fibre. Thresholds:
- WAN upload > 50 Mbps sustained: flag (possible data exfil)
- VLAN4 (DMZ) upload > 20 Mbps sustained: flag (validator should use 2-5 Mbps)
- VLAN2 (IoT) sustained > 100 Mbps: flag (unusual for IoT)

QNAP TS-932PX temperature thresholds:
- Normal CPU: 40–55°C | Alert: >60°C
- Normal disk: 30–45°C | Alert: >50°C

PBS VM identification: for any vm/ID or ct/ID flagged as stale, check if
the same ID appears in Proxmox health output to get the VM name. If not
visible, note "Proxmox UI lookup required for vm/[ID]."

Proxmox memory > 80%: flag as WARNING. Note whether this is trending
(check if infrastructure events show recent VM additions or memory changes).
```

---

### PROMPT-5: Wireless
**Langfuse slug:** `first-light-wireless`

**Current state:** Single tool querying 4 UniFi syslog event types — returns zero in most runs. Prompt asks for things the tool cannot provide.

**Rewrite strategy:** Be honest about what data is available. Use proxy signals from DNS until UniFi API tools are built (see DATA-4).

```
The wireless health tool queries UniFi syslog for deauth and anomaly events.
If all counts return zero, this indicates either a healthy wireless environment
or that the events are not being captured — not necessarily a clean bill of health.

When wireless tool returns empty or near-zero results:
1. Note that UniFi syslog events are not available or show no anomalies
2. Call query_adguard_top_clients(hours={hours}) and count clients on
   192.168.10.x (Guest VLAN) — this gives a proxy for guest WiFi activity
3. Report: approximate connected device count on each VLAN based on DNS
   activity (devices generating > 10 DNS queries in {hours}h)
4. Note: detailed wireless metrics (client RSSI, AP health, new device
   alerts) require UniFi Controller API integration — not yet available

Flag only if: deauth event count > 50 in a single hour (possible
deauth storm), or a guest VLAN client generates > 5,000 queries/day.
```

---

### PROMPT-6: Ethereum Validator
**Langfuse slug:** `first-light-validator`

**Current problems:**
- No balance delta — "32.012 ETH" is meaningless without yesterday's value
- No block proposal context — was one assigned? missed?
- No thresholds defined for peer counts or attestation effectiveness
- No instruction on what Nethermind `new_payload_ms` means or when to flag
- Validator VLAN context missing (VLAN 4, WAN-only DMZ)

**Key additions:**
```
Operational thresholds:
- Nimbus peers: normal > 50. Warning < 30. Critical < 10.
- Nethermind peers: normal > 25. Warning < 15.
- Source attestation effectiveness: normal > 99%. Warning < 97%. Critical < 95%.
- Head/target effectiveness: normal > 98%. Warning < 95%.
- Nethermind new_payload_ms: normal < 500ms. Warning > 1000ms (attestations
  will arrive late, reducing effectiveness).

Balance interpretation: the tool reports current balance. Without a prior
baseline, note the absolute value and flag if balance < 32.0 ETH
(net slashing/penalties). Expected earnings: ~0.00012 ETH per epoch
(~6.4 minutes), or ~0.02 ETH/month when attesting correctly.

Block proposals: if the tool returns proposal data, report whether any
proposals were assigned in the period and whether they succeeded.
A missed proposal (assigned but not submitted) = significant event.

Validator VLAN context: the validator is in VLAN 4 (DMZ, WAN-only).
If the validator tool cannot reach its metrics endpoint, this may indicate
a VLAN 4 connectivity issue rather than a validator failure.

Note: pfSense is currently blocking all inbound TCP/UDP to port 9000 from
WAN. This means other validators cannot initiate connections to this node —
only outbound-initiated P2P works. This limits peer discovery. If peer
count falls below 30, this firewall rule is the likely cause.
```

---

### PROMPT-7: Synthesis
**Langfuse slug:** `first-light-synthesis`

**Current problems:**
- No cross-domain correlation methodology — just hopes the LLM notices
- No instruction to resolve conflicting severity assessments between domains
- No baseline comparison (needs ARCH-4 to supply data)
- Domain summaries are unstructured markdown — re-parsing overhead

**Key additions:**
```
Cross-domain correlation — check these specific patterns:
1. Any IP appearing in BOTH firewall blocks AND DNS high-risk clients:
   correlate and report together, not separately.
2. bookstack (192.168.1.110) appears in DNS with high risk score AND in
   infrastructure as a running Proxmox container: treat together.
   A container with 99%+ DNS block rate is a compromise indicator.
3. Validator peer count vs firewall port 9000 block volume: if peer count
   < 30 AND port 9000 blocks > 10,000/day, recommend opening inbound
   port 9000 on pfSense DMZ WAN rule.
4. QNAP volume > 95% AND Frigate recording health: are both NVR systems
   (QVR Pro + Frigate) recording the same cameras simultaneously?

Conflicting severity resolution: if a domain agent flags something CRITICAL
that another domain agent's data explains as normal (e.g., validator P2P
traffic flagged by firewall but validator shows healthy peer count), resolve
it to the correct severity and note the resolution.

Report for a home operator who checks this once per day on Slack.
Be direct. If nothing needs attention, say so clearly in the summary.
Do not pad with "the network appears generally healthy" boilerplate.
```

---

## Track 3 — Data Gaps & Enrichment

**Goal:** Build missing tools and queries so the prompts can ask for data that actually exists.

---

### DATA-1: Per-client blocked domains tool
**Priority:** P1 — needed for DNS investigation of high-risk clients like bookstack
**Effort:** 2 days

AdGuard exposes a query log API at `/control/querylog` that supports filtering by client IP and response status. Add:

```python
@tool
def query_adguard_blocked_domains_for_client(
    client_ip: str, hours: int = 24, limit: int = 30
) -> str:
    """Get the specific blocked domain names for a single client from AdGuard query log.
    Use when a client has elevated risk score (>7) or block rate (>50%) to identify
    what categories of content are being blocked.
    Returns: list of blocked FQDNs with block counts and blocklist name."""
```

Endpoint: `https://adguard.mcducklabs.com/control/querylog?response_status=filtered&client_ip={ip}&limit={limit}`

Add to DNS agent tool list. Add to DNS prompt: "For any client with risk_score >= 7, call query_adguard_blocked_domains_for_client to get the actual blocked domain names."

---

### DATA-2: Validator balance delta (Redis-backed)
**Priority:** P1 — current balance metric is meaningless in isolation
**Effort:** 1 day

In `agent/tools/validator.py`, after fetching current balance:
1. Read `fl:validator:balance_prev` from Redis
2. Compute delta = current - previous
3. Write current balance back to Redis as new `_prev`
4. Include delta in tool output: `"balance_delta_gwei": +1234, "balance_trend": "earning"`

If no previous value exists (first run), return `"balance_delta_gwei": null, "balance_trend": "no baseline"`.

---

### DATA-3: Validator block proposals and attestation delay
**Priority:** P2
**Effort:** 1 day

Add to `query_validator_health` in `validator.py`:
- `validator_monitor_prev_epoch_block_production_success_total` — proposals made
- `validator_monitor_prev_epoch_block_production_attempt_total` — proposals assigned
- Per-slot attestation inclusion delay histogram (Nimbus exports as labeled counter)

These are already in the Nimbus `/metrics` endpoint — just need to be extracted.

---

### DATA-4: UniFi Controller API tools (wireless domain overhaul)
**Priority:** P1 — current wireless domain produces zero signal
**Effort:** 3 days

New file: `agent/tools/unifi.py`

```python
@tool
def query_unifi_clients() -> str:
    """Get currently connected WiFi clients from UniFi Controller.
    Returns per-AP client count, MAC addresses, RSSI, data usage,
    SSID, VLAN, and first-seen timestamp for new devices."""
    # GET https://unifi.mcducklabs.com:8443/api/s/default/stat/sta

@tool
def query_unifi_ap_health() -> str:
    """Get AP status: uptime, connected clients, channel, tx retry rate,
    channel utilisation. Flag APs with >20% retry rate (RF interference)."""
    # GET https://unifi.mcducklabs.com:8443/api/s/default/stat/device

@tool
def query_unifi_new_devices(hours: int = 24) -> str:
    """Get MAC addresses that connected for the first time in the last N hours.
    Cross-reference with known device list to flag genuinely new devices."""
    # Compare first_seen timestamps against threshold
```

Auth: uses `unifi_username` / `unifi_password` from config + session cookie.
Replace `query_wireless_health` in the wireless agent tool list with these three.

---

### DATA-5: AdGuard NXDomain rate per client
**Priority:** P2 — DGA and misconfiguration detection
**Effort:** 1 day

Add to `agent/tools/metrics.py`:

```python
@tool
def query_adguard_nxdomain_rates(hours: int = 24, limit: int = 10) -> str:
    """Get clients with highest NXDOMAIN (non-existent domain) response rates.
    High NXDOMAIN rate indicates: DGA malware probing random domains,
    misconfigured application, or DNS reconnaissance.
    Returns: client_ip, client_name, nxdomain_count, nxdomain_rate_pct"""
```

Requires `adguard_client_nxdomain_*` metrics from the AdGuard analytics exporter — check if these are exported. If not, query the AdGuard query log API with `response_status=NXDOMAIN`.

---

### DATA-6: pfSense outbound block query
**Priority:** P2 — internal lateral movement / exfil signal
**Effort:** 4 hours

Modify `query_security_summary` in `logs.py` (or add a new tool) to include:

```sql
-- Outbound blocks: internal devices blocked going outbound
SELECT src_ip, dst_ip, dst_port, count(*) as block_count
FROM pfsense_logs
WHERE action = 'block'
  AND src_ip LIKE '192.168.%'
  AND timestamp > now() - INTERVAL {hours} HOUR
GROUP BY src_ip, dst_ip, dst_port
ORDER BY block_count DESC
LIMIT 20
```

An internal device repeatedly hitting a blocked outbound destination is qualitatively different from external scans — it may be an IOC for malware attempting C2 and being stopped by pfSense.

---

### DATA-7: ntopng ARP table tool
**Priority:** P3 — new device detection on trusted VLANs
**Effort:** 4 hours

Add to `agent/tools/ntopng.py`:

```python
@tool
def query_ntopng_arp_table() -> str:
    """Get current ARP table from ntopng: IP-to-MAC mappings with MAC vendor.
    Use to detect new or unexpected devices on trusted VLANs.
    Flag any MAC vendor that is unexpected for the VLAN it appears on."""
    # GET /lua/rest/v2/get/arp/table.lua
```

Add to network_flow agent tool list with instruction: "Call every run. Flag any new MAC addresses not in the known device list."

---

### DATA-8: QNAP directory sizes auto-trigger
**Priority:** P1 (completes the current most-critical finding)
**Effort:** Already exists — it's a prompt change (PROMPT-4) not a tool change

`query_qnap_directory_sizes` already exists in `qnap_tools.py`. The gap is purely in the prompt — the agent needs explicit instruction to call it when volume > 85%. No code needed.

---

## Implementation Order

| Sprint | Tickets | Rationale |
|--------|---------|-----------|
| **Now (bugs)** | ARCH-1, PROMPT-4 (QNAP auto-call) | Template bug + QNAP critical finding — both < 1 hour |
| **Week 1** | PROMPT-1 through PROMPT-7 | All prompts, full rewrites, push to Langfuse |
| **Week 2** | DATA-1, DATA-2, DATA-4 | Per-client blocked domains, validator balance delta, UniFi tools |
| **Week 3** | ARCH-2 (correlation pass), DATA-3, DATA-6 | Architecture change + supporting data tools |
| **Week 4** | ARCH-3 (structured outputs), ARCH-4 (Redis baseline), DATA-5, DATA-7 | Foundation for long-term trend analysis |

ARCH-5 (token budget / model routing) deferred until after structured outputs (ARCH-3) since model selection should follow from output complexity, not precede it.
