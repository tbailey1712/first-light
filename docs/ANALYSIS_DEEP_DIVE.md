# First Light AI — Deep Security Analysis & Prompt Engineering Review

*Analysis date: 2026-04-02*
*Based on: full codebase review + live Langfuse trace `3e48cc0649a278e2371695ed60a42fa5`*

---

## A. Current Architecture Assessment

### How the pipeline actually works

Six domain agents run in parallel via LangGraph `Send` fan-out from a shared `initialize` node that fetches all Langfuse prompts upfront. Each domain agent runs a bounded ReAct loop (max 12 iterations, `agent_type="micro"`) and returns a markdown string. Those six strings are concatenated into a single user message handed to a synthesis agent (one non-tool LLM call with `agent_type="synthesis"`). The synthesis agent has no tools and no ability to ask follow-up questions.

**LangGraph execution order from the trace:**

| Domain | LLM calls | Total tokens | Notes |
|---|---|---|---|
| firewall_threat | 2 | ~12,700 | 5 tools in first call, no second tool round |
| dns_security | 3 | ~15,000 | 6 tools first call, 2 more second, final answer third |
| network_flow | 3 | ~32,600 | 9 tools first call, burned 2 calls paging flows |
| infrastructure | 2 | ~13,300 | First call dispatches tools, second summarises |
| wireless | 2 | ~1,900 | Only 1 tool, near-instant |
| validator | 2 | ~2,600 | Only 1 tool, near-instant |
| synthesis | 1 | ~9,500 | One-shot LLM call with 6 summaries as input |

**Total run cost: ~87,600 tokens across 15 LLM generations** (single run).

### What the ReAct loop does

`run_react_loop` in `agent/llm.py` builds a simple message list starting with `[system, user]` and calls `chat()` in a loop. Each iteration:
1. If the model returns `tool_calls`, it executes them, appends `role="tool"` results to messages, and loops.
2. If the model returns plain text (no tool calls), that text is the final answer.
3. If the loop hits `MAX_TOOL_ITERATIONS=12`, it appends a hard "give me your final summary now" message.

Tool results are truncated at `MAX_TOOL_RESULT_CHARS=10,000` characters. The whole conversation history is carried forward every iteration — this is where the `network_flow` agent hit 18k+ input tokens on its third call.

### What agents actually call vs what's available

**firewall_threat** (7 tools available, 5 called in first round):
- Called: `query_threat_intel_summary`, `query_security_summary`, `query_auth_events`, `query_crowdsec_alerts`, `query_crowdsec_decisions`
- Never called: `lookup_ip_threat_intel`, `query_threat_intel_coverage`
- The agent correctly identified no IP had score > 50, so skipping `lookup_ip_threat_intel` was correct. `query_threat_intel_coverage` was skipped entirely — it would have shown whether the enricher had good coverage that day.

**dns_security** (8 tools available, 8 called across 2 rounds):
- Round 1: all 6 listed tools called in parallel
- Round 2: `query_adguard_top_clients`, `query_adguard_block_rates` — these are the two the prompt listed as "if needed"
- Full coverage achieved in 3 calls. This agent is well-prompted.

**network_flow** (11 tools available, 10 called across 3 rounds):
- Round 1: 9 tools in parallel — good parallel dispatch
- Round 2: `query_ntopng_active_flows` (page 1) — 10,059 chars of flow data, then immediately requested page 2
- Round 3: `query_ntopng_active_flows` page 2 — another 10,058 chars
- The agent burned 2 iterations and ~28k chars paging through raw flow data, then produced a clean report. This is a significant token waste. `query_ntopng_host_details` and `query_ntopng_host_l7_stats` were never used.
- Never called: `query_ntopng_arp_table` (could detect new/unexpected MAC addresses)

**infrastructure** (11 tools, ~8 called):
- First call dispatched 8 tools in one parallel round; second call synthesised the results.
- Tools never called: `query_uptime_kuma_uptime` (daily uptime %), `query_switch_port_errors` and `query_pfsense_interface_traffic` were in the tool list but trace shows they may have been called from here OR network_flow; hard to confirm. The infrastructure prompt specifically lists them.

**wireless** (1 tool, 1 called):
- Structurally impoverished. One tool, one call. Returns empty results or near-empty. Costs ~1,900 tokens for effectively no signal. The tool itself (`query_wireless_health`) queries for `deauthenticated`, `disassociated`, `client_anomaly`, `ageout` events from UniFi logs — but does not surface: connected client count, SSID utilisation, rogue AP detection, client signal quality, or new device alerts.

**validator** (1 tool, 1 called):
- Single tool `query_validator_health` that hits Nimbus + Nethermind Prometheus endpoints directly. Appropriate for this domain. But the tool does not pull: attestation inclusion delay, sync committee participation, block proposal history, or balance delta vs yesterday.

---

## B. Prompt Quality Analysis

### The `{hours}` template variable bug

**This is a real bug with real impact.** The system prompts stored in Langfuse contain literal `{hours}` placeholders — for example the wireless prompt says `query_wireless_health(hours={hours})`. The `initialize()` node calls `manager.get_prompt(slug, hours=hours)` which substitutes the variable correctly *if* the Langfuse SDK template interpolation works. From the live trace, the system prompt delivered to the DNS agent reads:

```
query_adguard_network_summary(hours={hours}) — START HERE
```

**This means the substitution is NOT happening.** The `{hours}` placeholder is arriving verbatim to the LLM. The model is intelligent enough to infer `hours=24` from the user message ("Analyse DNS security activity for the past 24 hours"), but it is making an inference rather than being told explicitly. If the report were run for 6 hours or 48 hours, the tool call arguments would be wrong — the model might still call with `hours=24` because that's what the system prompt template implies.

The fix is straightforward: either ensure Langfuse template substitution is working (verify `manager.get_prompt(slug, hours=hours)` passes the hours variable as a template variable in the Langfuse prompt definition), or compile the prompts at call time in Python before sending. The latter is safer.

### Synthesis prompt: what it does well and what's missing

**What it does well:**
- Clean structure with severity icons
- Network context with VLAN isolation rules
- Report template with section headers
- "Omit sections with nothing to say" rule — good for Telegram

**What's missing from the synthesis prompt:**
1. No instruction to perform IP-level cross-domain correlation. The synthesis agent received the firewall agent's output mentioning "169.150.222.204 hit port 9000 11,400 times" and the validator agent's output showing the validator is healthy — but it never attempts to check whether those port 9000 probes are legitimate Ethereum P2P discovery (they almost certainly are). The prompt says "identify cross-domain correlations" but gives no examples or methodology.
2. No instruction on how to handle conflicting severity assessments. The firewall agent flagged port 9000 traffic as "CRITICAL: Cross-VLAN Traffic" — which it isn't (it's inbound WAN to the DMZ VLAN, which is exactly what a validator should receive). The synthesis agent correctly overrode this to INFO, but only because the network context in the synthesis prompt mentioned VLAN 4 is WAN-only. This worked by luck of context; it should be explicit.
3. No baseline comparison. The synthesis agent doesn't know if 74,580 DNS queries is high or low vs yesterday. It has no memory.
4. No instructions for the weekly trend signal: "note any metrics that are trending toward thresholds."
5. Token efficiency: synthesis input was 7,029 tokens, output was 2,460 tokens. The six domain summaries going in are unstructured markdown — the synthesis agent has to re-parse them. A structured JSON format from domain agents would be more token-efficient and reduce hallucination risk.

### Per-domain prompt assessment

**firewall_threat:** Good. Specific tool order, specific threshold (>50 = malicious), explicit cross-VLAN rule. One gap: no instruction to correlate port 9000 blocks with the known validator P2P port — the agent flagged 28k+ inbound attempts to 192.168.4.2:9000 as "CRITICAL: Cross-VLAN Traffic" when this is absolutely expected for an Ethereum validator. The synthesis agent caught this, but it should be caught earlier.

**dns_security:** Strong. Clear DHCP fingerprinting instruction, good IoT anomaly signal definition. The `{hours}` template bug applies here but the agent compensated. Minor gap: no instruction to specifically look for C2 beaconing signatures (periodic queries to DGA-like domains), no instruction to correlate new DHCP devices with MAC vendor lookups, no instruction to flag DNS-over-HTTPS bypasses (devices that stop using AdGuard suddenly).

**network_flow:** Good false-positive suppression (RTSP, ntopng CE limitations, cumulative counter notes). Major gap: the agent burned 2 iterations of its 12-iteration budget and ~28,000 chars of context window paging through raw active flow JSON looking for something interesting. It found nothing new. The prompt should either instruct the agent to only call `query_ntopng_active_flows` when a specific anomaly was detected upstream, or limit `perPage` to 10. The current behaviour is: "I found nothing interesting, let me page through 60 flows anyway."

**infrastructure:** Good tool coverage. One structural gap: the prompt says "check pfSense WAN/VLAN interface utilization" but provides no threshold — the agent dutifully calls the tool and gets bandwidth numbers but has no basis to call any of them anomalous. Define: "Flag WAN utilisation >80% of link speed. The WAN link is [X] Mbps." Similarly for QNAP temperatures, the tool fires alerts at >65°C but the prompt doesn't mention what's normal.

**wireless:** Critically underpowered. The single tool `query_wireless_health` queries for 4 event types. In the live trace, ALL 4 returned empty. The agent had no choice but to say "everything is fine." The wireless domain is essentially blind. Problems:
- No connected client count or per-SSID device count
- No rogue AP detection
- No new device alerts (first time a MAC address connected)
- No signal quality data (RSSI, noise floor)
- No bandwidth per SSID
- No guest network usage
- No way to detect a device that connected and then did something malicious

**validator:** Functional but shallow. The tool reports: sync status, peer counts, attestation effectiveness (source/head/target), balance, slashed flag, exited flag. Missing:
- Attestation inclusion delay (how many slots late were attestations included?)
- Balance delta (did balance go up or down vs previous check?)
- Block proposals in period: were any assigned? Were any missed?
- Sync committee participation (if the validator is in a sync committee)
- Time since last Nimbus/Nethermind restart
- Whether the execution client (Nethermind) is keeping up with head (`new_payload_ms`)
- MEV boost status / relay connectivity

---

## C. Data Coverage Gaps by Domain

### Firewall / Threat Intelligence

**Tools exist but underused:**
- `lookup_ip_threat_intel` is only called for IPs with score > 50. In the live run there were none, so it was never called. But there were IPs with scores of 25 (Amazon AWS) — the prompt should instruct the agent to look up the top 3 IPs by block count regardless of score when that count is >1000.
- `query_threat_intel_coverage` was never called. This would show whether the enricher is working and what percentage of blocked IPs have been enriched. Useful diagnostic.

**Data available but not queried:**
- `query_security_summary` includes ntopng alerts, but the agent doesn't specifically look at which ntopng alert types are firing. In the live trace, 3 "error" severity ntopng alerts were present — their type is not visible in the firewall summary.
- pfSense interface-level filtering: the firewall block query filters only `pfsense.action = 'block'` on external IPs. There's no query for `pass` events to unusual internal destinations (LAN-side lateral movement), no query for `block` events on internal-to-WAN for unexpected outbound connections.
- The firewall agent has no awareness of which pfSense interface each block came in on. Blocks on `em0` (WAN) are different from blocks on `opt1` (VLAN2) — an internal device trying to reach outside its VLAN is very different from an external scan.
- No query for pfSense NAT table or state table size — a state table exhaustion attack wouldn't be visible in block logs.

**Correlations not made:**
- Port 9000 blocks: 28,236 attempts to 192.168.4.2:9000. These are Ethereum P2P discovery attempts. They are NOT attacks — they are other validators trying to peer. But the firewall agent has no knowledge of this because the validator port is not in the system prompt. The system prompt should explicitly say: "192.168.4.2 is the Ethereum validator. Port 9000 TCP/UDP is the Ethereum P2P port. Inbound blocks to this port are normal validator network activity. Do NOT flag these as attacks."
- IP 171.102.145.67 (AbuseIPDB score: 15, TRUE INTERNET Thailand) appeared in both the threat intel summary (6,063 blocks to port 9000) and was the highest-scored IP. The agent correctly noted it. But it didn't cross-check with CrowdSec: is this IP banned? (It was not, since CrowdSec showed 0 active bans.)

### DNS Security

**Tools exist but underused:**
- `query_adguard_threat_signals` returned anomaly counts but the full content of what anomalies were found is in the AdGuard database, not in the metrics. There is 1 unacknowledged medium-severity anomaly — but the agent can only report its existence, not what triggered it.
- The `search_logs_by_ip` tool from `logs.py` is NOT in the DNS agent's tool list. This is a gap: if a high-risk DNS client is identified, the agent should be able to cross-check what that IP is doing in firewall logs.

**Missing security questions the DNS agent should be answering:**
1. Is bookstack (192.168.1.110, 99% block rate) actually compromised, or is it just hitting a blocklist false positive? The agent identified it as suspicious but had no way to check what specific domains were blocked.
2. Are any clients querying TXT records at unusually high rates? (DNS tunnelling indicator — not detectable with current tools)
3. Are any newly-appeared clients (first seen in last 24h) querying C2-style domains?
4. What is the guest network (192.168.10.x) DNS usage? None of the clients in the trace appear to be from VLAN 10.
5. Did any IoT device (192.168.2.x) suddenly start querying domains it never queried before? The DHCP fingerprinting tool gives top domains but not "new domains not seen before."

**Data available in AdGuard but not exposed:**
- Per-client query log (individual query history) — would identify specific blocked domains for bookstack
- Query type distribution (A, AAAA, TXT, MX) — TXT spike = tunnelling
- NXDomain rate per client — high NXDOMAIN = DGA activity or misconfiguration
- Response time distribution — unusually slow responses may indicate DNS poisoning attempts

### Network Flow (ntopng)

**Massive token waste:**
The network_flow agent called `query_ntopng_active_flows` three times (page 1, page 2, then summary) consuming ~28k chars of context for raw flow JSON. The prompt should explicitly say: "Only call `query_ntopng_active_flows` if you have identified a specific host or protocol worth investigating. Do NOT page through flows speculatively." In the trace the agent got 60 raw flows, saw nothing unusual, and wrote its final summary — but burned 2 of its 12 loop iterations doing so.

**Tools available but never called:**
- `query_ntopng_arp_table`: would show all IP-to-MAC mappings. New MACs = new devices. Unexpected MACs on trusted VLANs = network intrusion.
- `query_ntopng_host_details` and `query_ntopng_host_l7_stats`: these are investigation tools called only when a specific suspicious host is identified. Fine that they weren't called in a clean run.

**Security questions not being asked:**
1. Are there any flows from 192.168.3.x (Camera VLAN) to destinations OTHER than 192.168.2.7 (Frigate) and 192.168.2.9 (NAS)? The prompt calls out this as a CRITICAL anomaly pattern but only instructs the agent to "check VLAN traffic breakdown" — it doesn't know the specific expected destinations.
2. Are there any flows FROM 192.168.4.x (Validator/DMZ) TO any internal subnet? The validator should have zero inbound-initiated internal flows.
3. What is the Validator VLAN (192.168.4.x) outbound bandwidth? Unusually high could indicate the validator node is compromised for cryptomining or data exfil.
4. Are there any QUIC/UDP port 443 flows to unexpected destinations from IoT devices? This is a DNS-over-HTTPS bypass signal.
5. What are the top-traffic switch ports and do they map to expected devices? Switch port 21 (for example) handling 50GB/day when it's connected to a printer is suspicious.

**Country data limitation:**
`query_ntopng_top_countries` returned "not available in Community Edition." This is a real gap — geographic anomaly detection is fully absent. The only way to get country data is through `query_threat_intel_summary` which only covers blocked IPs, not active flows.

### Infrastructure

**Structural gaps:**
- QNAP event log query failed in the live run with no diagnostic details. The error is swallowed: `query_qnap_events` returns an error JSON but the synthesis just noted "QNAP Event Log Query Failed." There should be a retry or a specific error message distinguishing "ClickHouse timeout" from "QNAP syslog not configured" from "no events."
- `query_qnap_directory_sizes` is never called. The QNAP volume is at 99.8% full — but the agent doesn't drill down to identify what's consuming that space. This is the most critical finding of the entire report and the agent stops at "volume is 99.8% full" without calling `query_qnap_directory_sizes("/share/...")`.
- PBS stale backup finding is excellent — 5 VMs/CTs not backed up is correctly flagged. But PBS doesn't tell you the VM *names* for vm/100, ct/110, ct/111 — these appear in the output without names. The agent should note: "Cannot identify these VMs by name without Proxmox API — check Proxmox UI to identify vm/100."
- Proxmox memory at 81%: the agent noted this is "within acceptable range" but didn't ask: what is the trend? Is this normal for this time of day? Is it growing?
- No check for Proxmox backup job schedule: are the backup jobs *configured* for those VMs, or have the jobs been deleted?

**Tools available but not used:**
- `query_qnap_directory_sizes` — should be called automatically when any volume exceeds 85% to identify top space consumers.
- `query_uptime_kuma_uptime` — the agent called `query_uptime_kuma_status` and `query_uptime_kuma_incidents` but potentially not `query_uptime_kuma_uptime`. The daily uptime % per service is more useful for trend analysis.

**Missing data entirely:**
- No Home Assistant (HA) integration health check. HA errors appear in `query_infrastructure_events` but there's no dedicated HA tool. If HA is down, it may be visible only as an absence of HA-sourced events.
- No Docker container resource usage (which container is using the most CPU/RAM on the Docker host).
- No pfSense CPU/memory/state table metrics — pfSense health is only visible through its SNMP interface traffic, not its internal health.
- No check for certificate expiry on internal services.

### Wireless

This domain is the weakest in the entire system. The single tool returns counts of 4 event types from UniFi syslog. In practice it almost always returns zero for all 4, and the agent writes a boilerplate "everything is fine" message.

**What this domain should be checking but can't:**
1. How many clients are connected right now across all SSIDs and VLANs?
2. Have any new MAC addresses connected that have never been seen before?
3. Is any device on the Guest VLAN (192.168.10.x) generating unusual traffic volume?
4. Are there any rogue APs detected (SSIDs broadcasting our SSID name)?
5. What is the client distribution across 2.4GHz vs 5GHz vs 6GHz bands?
6. Are any clients experiencing poor signal quality (RSSI < -75 dBm)?
7. Is any AP showing high retry rates (indicating RF interference)?
8. Has any client been associated unusually long (potential persistent attacker)?

**Why the tool is empty:**
The `query_wireless_health` query only matches 4 event types in UniFi syslog. UniFi may not be generating these specific events, or they may be stored under different attribute names than expected. The wireless agent should at minimum fall back to `query_adguard_top_clients` filtered to 192.168.10.x (guest VLAN) and 192.168.1.x device count to infer wireless activity indirectly.

**Path forward:**
The UniFi Controller API (`unifi.mcducklabs.com:8443/api`) would provide: site stats, client count per AP, connected client list with MACs, RSSI per client, data usage per client. This needs a dedicated UniFi tool (`query_unifi_clients`, `query_unifi_aps`). The current wireless domain is collecting log events when the real signal is in the controller API.

### Validator

**What the tool reports well:** sync status, peers, attestation effectiveness (source/head/target), balance, slashed/exited flags.

**What's missing from the validator tool:**
1. **Balance delta**: the tool reports current balance but not the change since last check. A single run seeing "32.012ETH" doesn't tell you if it went up (earning) or down (being penalised). Need to store/compare previous balance.
2. **Attestation inclusion delay**: `validator_monitor_prev_epoch_on_chain_attester_hit_total` counts hits but not *how late* they were included. Inclusion delay > 2 slots indicates the validator is seeing blocks late, possibly due to network latency or the execution client being slow.
3. **Block proposals**: Was the validator assigned to propose a block in the last 24h? If yes, was it successful? `validator_monitor_prev_epoch_block_production_success_total` and `prev_epoch_block_production_attempt_total` are available in Nimbus metrics.
4. **Sync committee**: If the validator is in a current sync committee (elected every ~27 hours), its sync committee contributions should be near-perfect. `validator_monitor_sync_committee_period_total` tracks this.
5. **MEV-Boost/relay health**: If the validator is using MEV-Boost, relay connectivity is critical. Not checked at all.
6. **Nethermind new_payload_ms**: This IS reported by the tool (currently ~unknown in most runs) — it's the time the execution client takes to execute a new payload. Values >1000ms indicate the execution client is struggling and attestations will be late.
7. **Chain reorganizations**: `nethermind_reorganizations` is reported by the tool but the prompt doesn't instruct the agent what value is "too high." Reorgs > 5 fires an alert, but the operator doesn't know if this is normal.

**The validator is in VLAN 4 (DMZ) — WAN only.** The firewall/threat agent is seeing 28,236 inbound blocks to 192.168.4.2:9000. These are Ethereum P2P discovery attempts from other nodes. They're being BLOCKED by pfSense. This means the validator is somewhat isolated from the Ethereum network — it can only reach peers it initiates connections to, not peers that try to reach it. This likely explains the relatively low peer counts. This is a critical cross-domain insight that no agent currently surfaces.

---

## D. Cross-Domain Correlation Opportunities

The synthesis agent currently receives 6 text blobs and tries to find correlations from natural language. This is the most significant architectural weakness. Here are the specific correlations that should be automated:

### Correlation 1: Inbound port 9000 blocks → Validator peer count

**Current state:** Firewall agent flags 28,236 port 9000 blocks as "CRITICAL: Cross-VLAN Traffic." Validator agent reports peer count is fine. Synthesis agent resolves the contradiction.

**Better approach:** The firewall agent should know that 192.168.4.2 is the Ethereum validator and port 9000/UDP+TCP is its P2P port. The synthesis agent should specifically cross-check: "Validator has X peers. WAN port 9000 is being blocked by pfSense. Are these related?" — and note that opening inbound 9000 on the pfSense DMZ rule would improve peer discovery.

**Specific question the system should answer:** If inbound P2P is blocked and peer count falls below 10, that's a root-cause chain: pfSense blocking → poor discoverability → low peers → attestation risk.

### Correlation 2: bookstack (192.168.1.110) 99% DNS block rate → no Proxmox confirmation

**Current state:** DNS agent flags bookstack at risk score 9.91. Infrastructure agent confirms bookstack container is running in Proxmox. Synthesis agent connects these correctly.

**What's missing:** Neither agent checks what *specific domains* bookstack is querying. A compromised container that can't reach its C2 (because AdGuard blocks the C2 domain) would look exactly like this: high block rate, still running, no other obvious anomaly. The synthesis agent should flag: "bookstack risk score 9.91 — requires manual review of blocked domain list in AdGuard. A container with 99% block rate that is still running may be attempting C2 communication being intercepted by DNS filtering."

**Tool needed:** A query against AdGuard's query log API for the specific blocked domains for 192.168.1.110 in the last 24h. This doesn't exist in the current metrics toolset — the metrics only expose aggregate block counts, not individual queries.

### Correlation 3: New DHCP devices → ntopng host details → threat intel

**Current state:** DNS agent identifies DHCP devices by their DNS fingerprint. ntopng shows active hosts. Neither cross-references the other.

**Better approach:** When the DNS agent identifies an unknown DHCP device (e.g., 192.168.1.227 with 290 queries but unclear fingerprint), the network_flow agent should be checking if that same IP appears in `query_ntopng_active_hosts` with unusual traffic volume, and the firewall agent should be checking if it appears in `search_logs_by_ip`. This can't happen with the current fan-out architecture because agents run in parallel with no shared state.

**Proposed fix:** Add a "correlation pass" after the 6 domain agents complete, before synthesis. This pass receives all 6 summaries, extracts suspicious IPs/devices, and runs targeted cross-domain lookups using `search_logs_by_ip` and `lookup_ip_threat_intel`.

### Correlation 4: QNAP volume 99.8% → Frigate recording health → camera VLAN traffic

**Current state:** Infrastructure agent identifies QNAP QVRProSpace_Vault1 at 99.8%. Frigate is reported separately as healthy at 72.5% used. Network flow agent shows continuous RTSP streams from cameras.

**What the system doesn't ask:** How long until QVRProSpace_Vault1 fills up? At what rate is it consuming space? Is QVR Pro (QNAP's NVR) generating the same volume as Frigate? Why does the NAS have a separate 8.8TB surveillance volume when Frigate's 1.7TB is only 72% used? Are both NVR systems recording the same cameras simultaneously (doubling storage consumption)?

**Tool needed:** `query_qnap_directory_sizes` should be called automatically when any volume exceeds 85%. Currently this must be manually triggered.

### Correlation 5: CrowdSec decision count (0) vs pfSense block volume (28k+)

**Current state:** Both the firewall agent and the synthesis agent mention "0 active CrowdSec bans" and "28k+ port 9000 blocks." But no one asks: why isn't CrowdSec banning these IPs?

**The answer:** CrowdSec's pf-scan-multi_ports scenario fires on port *scanning* (multiple ports), not on repeated attempts to a *single port*. The 28k blocks are all to port 9000 from many different IPs — this is a distributed scan of a specific port, not a single IP scanning many ports. CrowdSec's scenario for this pattern (`crowdsecurity/port-scan`) may not be configured or may require different thresholds.

**Missing question:** Does pfSense/CrowdSec have a scenario that would detect "many IPs from different countries all targeting the same port on the same internal IP"? If not, this is a gap in the IDS configuration.

### Correlation 6: SSH login volume on docker host (112 times from 192.168.1.70)

**Current state:** Auth events tool shows 112 SSH logins to `docker` host from 192.168.1.70 (tbailey, publickey). The firewall agent notes "all from 192.168.1.70 — internal network, OK."

**What should be flagged (and isn't):** 112 SSH logins in 24h is high for a single operator. This likely indicates automated SSH tunnels (VS Code Remote SSH, SSH port forwarding, or monitoring scripts that reconnect). While probably benign, the system should note: "112 SSH sessions to docker host in 24h from 192.168.1.70 — confirm this is expected automation. Consider certificate pinning or ProxyJump if these are VS Code or automated monitoring connections."

### Correlation 7: Wireless domain → DNS guest VLAN monitoring

**Current state:** Wireless agent reports "nothing to report." DNS agent reports client counts but doesn't break them down by VLAN.

**Missing:** Is anyone on the Guest VLAN (192.168.10.x) doing anything suspicious? The DNS agent sees queries from all VLANs but doesn't specifically highlight guest VLAN activity. The wireless agent has no visibility into guest network usage.

---

## E. Specific Recommendations by Domain

### Firewall & Threat Intelligence

**1. Add validator P2P context to system prompt:**
```
Known-good traffic patterns — do NOT flag these as attacks:
- 192.168.4.2 is the Ethereum validator. Port 9000 TCP/UDP is the Ethereum LibP2P
  discovery port. Inbound blocks to 192.168.4.2:9000 from internet IPs are other
  validators attempting to peer — this is NORMAL Ethereum network activity.
  Report the volume as informational, not as an attack.
- High block volume to port 9000 from diverse global IPs (Amazon, OVH, hosting providers)
  is the expected signature of Ethereum network scanning. Not malicious.
```

**2. Change `lookup_ip_threat_intel` trigger:**
Currently the prompt says "for any IP with score > 50 (max 5 IPs)." Change to: "for the top 3 IPs by block_count where block_count > 1000, regardless of threat score." This surfaces investigation data on persistent scanners even if they haven't been reported to threat intel databases yet.

**3. Add interface-level block analysis:**
Add a new ClickHouse query (or modify `query_security_summary`) to show firewall blocks broken down by pfSense interface: `pfsense.interface`. Blocks on `opt2` (IoT VLAN) or `opt3` (CCTV VLAN) are qualitatively different from WAN blocks.

**4. Add outbound block query:**
Currently only inbound external blocks are queried. Add: `WHERE attributes_string['pfsense.action'] = 'block' AND attributes_string['pfsense.src_ip'] LIKE '192.168.%'` — this surfaces internal devices trying to reach blocked destinations, which is a lateral movement or exfil signal.

**5. Add `query_threat_intel_coverage` to standard tool calls:**
The agent should always call this first to establish baseline: "what % of blocked IPs have threat intel enrichment today?" If coverage drops below 50%, the enricher may have hit rate limits or failed.

---

### DNS Security

**1. Fix the `{hours}` template variable** (affects all 6 domain prompts):
In the Langfuse prompt definition, verify that `{hours}` is defined as a template variable. If not, add it. Or switch to Python-side formatting before passing the prompt to the agent:
```python
# In daily_report.py, after fetching prompt:
system = prompt_override.format(hours=hours)
```
This ensures the hours value is always correct regardless of Langfuse template behaviour.

**2. Add AdGuard query log tool for investigation:**
When a client has a risk score > 7, the agent needs to be able to see *which specific domains* are being blocked. Add:
```python
@tool
def query_adguard_blocked_domains_for_client(client_ip: str, hours: int = 24, limit: int = 20) -> str:
    """Get the specific blocked domain names for a single client IP from AdGuard query log."""
```
This requires either the AdGuard API (`/control/querylog?client_ip=X&response_status=filtered`) or a ClickHouse query against AdGuard query log data if it's being piped through.

**3. Add guest VLAN DNS monitoring to prompt:**
```
- 192.168.10.x clients are on the Guest WiFi VLAN. Guest clients generating more than
  500 queries/day or querying non-CDN/streaming domains warrants investigation.
  Note the count of active guest VLAN clients in your summary.
```

**4. Add NXDomain rate query:**
DNS amplification, DGA, and misconfiguration all show as elevated NXDomain rates. Add a metric or ClickHouse query against AdGuard logs for NXDomain response rates per client.

**5. Add DNS-over-HTTPS detection:**
If an IoT device (192.168.2.x) suddenly stops making DNS queries (drops from its normal volume to near-zero), it may have switched to DoH bypassing AdGuard. The `query_adguard_top_clients` results can be compared against the expected device list to detect "silent devices" that should be querying DNS.

---

### Network Flow

**1. Prevent speculative flow paging:**
Add to system prompt:
```
10. query_ntopng_active_flows() — ONLY call this tool if you have identified a specific
    suspicious host or anomalous protocol from the steps above. Do NOT page through flows
    speculatively. If you do call it, use perPage=10 and only request page 2+ if page 1
    contains clear evidence of ongoing anomalous activity requiring investigation.
```

**2. Add explicit VLAN isolation rules with expected endpoints:**
Replace the vague "flag traffic from isolated VLANs":
```
VLAN isolation rules (any deviation = CRITICAL):
- Camera VLAN (192.168.3.x): May ONLY initiate flows TO 192.168.2.7 (Frigate) and
  192.168.2.9 (NAS) on port 554 (RTSP). Any flow from 192.168.3.x to WAN or to any
  other internal IP = CRITICAL security event.
- Validator VLAN (192.168.4.x): May initiate flows TO internet only (validator P2P,
  beacon API). Any flow FROM internet TO 192.168.4.x on port OTHER than 9000 = investigate.
  Any flow from 192.168.4.x to internal subnets (192.168.1.x, 192.168.2.x) = CRITICAL.
```

**3. Add validator outbound bandwidth monitoring:**
Add a specific check: "Report the total bytes_in and bytes_out for 192.168.4.x (Validator VLAN) from `query_ntopng_vlan_traffic`. Normal validator traffic is primarily outbound P2P (~2-10 Mbps sustained). Unexpected spikes in either direction warrant investigation."

**4. Add ARP table to standard tool calls:**
`query_ntopng_arp_table` should be called every run. New MAC addresses on trusted VLANs that don't match known device list = new device alert. Add to system prompt: "Call `query_ntopng_arp_table` and compare result to the known device list. Flag any MAC address not in the list below: [enumerate known devices]."

**5. Add switch port-to-device mapping context:**
The switch port traffic report shows bytes per port name (GigabitEthernet1, GigabitEthernet5, etc.) but the prompt has no knowledge of which port connects to which device. Add a port map to the system prompt:
```
Switch port assignments (TP-Link TL-SG2424):
- Port 1: pfSense WAN uplink
- Port 2: pfSense LAN (VLAN trunk)
- Port X: NAS (docker.mcducklabs.com)
- Port Y: Proxmox
[etc. — fill in actual port assignments]
```

---

### Infrastructure

**1. Auto-call `query_qnap_directory_sizes` when volume > 85%:**
Add to system prompt:
```
IMPORTANT: If query_qnap_health() shows any volume at >85% utilisation, you MUST
immediately call query_qnap_directory_sizes(path="/share/CACHEDEV1_DATA") to identify
the top space-consuming directories. Report the top 5 directories by size alongside
the volume utilisation alert. This is required — do not skip this step.
```

**2. Add WAN link capacity to interface traffic thresholds:**
```
Interface utilisation thresholds:
- WAN (pppoe0 or em0): Alert if >200 Mbps sustained (link is 500/500 Mbps fibre)
  or if upload > 50 Mbps sustained (could indicate outbound data exfil)
- VLAN1 (LAN): Alert if >400 Mbps (unusual for home network)
- VLAN2 (IoT): Alert if >100 Mbps sustained (IoT devices shouldn't need this)
- VLAN4 (DMZ/Validator): Alert if upload >20 Mbps sustained (validator normally
  uses 2-5 Mbps; higher could indicate validator compromise)
```

**3. Add Proxmox VM name resolution:**
The PBS backup tool returns `vm/100`, `ct/108` etc. without names. Add to prompt: "For any VM or CT shown as stale in PBS results, cross-reference with Proxmox health output to get the VM name. If the name is not visible, note that Proxmox API/UI lookup is required to identify vm/[ID]."

**4. Add QNAP temp thresholds:**
```
QNAP temperature thresholds (TS-932PX):
- Normal CPU temp: 40-55°C
- Normal disk temp: 30-45°C
- Alert: CPU >60°C, Disk >50°C, System >55°C
```

**5. Add PBS retention policy check:**
When stale backups are found (>26h), also check: "Is there a backup job configured for this VM/CT? A missing backup job is different from a failed backup job. Look for VMs/CTs with 0 backup jobs configured."

---

### Wireless

This domain needs a significant investment to be useful. The current single-tool approach will never produce actionable signal.

**Priority 1: Build a UniFi API tool**
```python
@tool
def query_unifi_clients() -> str:
    """Get currently connected WiFi clients from UniFi Controller.
    Returns: client count per SSID/AP, MAC addresses, RSSI, data usage."""
    # Hit https://unifi.mcducklabs.com:8443/api/s/default/stat/sta
    # or the UniFi Network Application API

@tool
def query_unifi_ap_health() -> str:
    """Get AP health: uptime, client count, channel utilisation, interference."""
    # Hit https://unifi.mcducklabs.com:8443/api/s/default/stat/device
```

**Priority 2: Add DNS-based wireless proxy signal**
Until a UniFi tool exists, add `search_logs_by_ip` from `logs.py` to the wireless agent's tool list and instruct it to check for 192.168.10.x (Guest VLAN) activity in firewall and DNS logs:
```
As a fallback until UniFi API tools are available:
- Call query_adguard_top_clients(hours={hours}) and filter for 192.168.10.x IPs
  to get guest network usage
- Note the count of active wireless clients on each VLAN from DNS query volume
```

**Priority 3: Rewrite wireless system prompt entirely:**
The current prompt asks for things the available tool cannot provide. The prompt should be honest about data limitations and use available proxy signals.

---

### Validator

**1. Add validator network context to firewall agent (critical fix):**
The firewall agent needs to know 192.168.4.x is the Ethereum validator. Without this, every inbound port 9000 attempt will be misclassified as a cross-VLAN attack.

**2. Add balance delta tracking:**
Requires either storing previous balance in Redis or querying the beacon API for the balance history endpoint. Short term, add to the tool: `beacon_api_balance_history` that hits `http://vldtr.mcducklabs.com:5052/eth/v1/beacon/states/head/validator_balances` to get current balance, then compare with the value stored in Redis from the previous run.

**3. Add block proposal check:**
Add a query for `validator_monitor_prev_epoch_block_production_success_total` and `validator_monitor_prev_epoch_block_production_attempt_total` to the validator tool. Then add to prompt: "Report whether any block proposals were assigned and whether they were successful. A missed proposal (assigned but not submitted) is a significant event."

**4. Add attestation inclusion delay:**
Add `validator_monitor_prev_epoch_on_chain_attester_hit_total` breakdown by inclusion delay slot. Nimbus exports this as a histogram. Even a basic "was average inclusion delay > 2 slots?" check would be valuable.

**5. Enrich prompt with validator operational context:**
```
Operational context:
- Normal peer count: Nimbus >50 peers, Nethermind >25 peers
- Normal source attestation effectiveness: >99%
- Normal head/target effectiveness: >98%
- Warning threshold: source < 97%, head < 95%
- The validator is in VLAN 4 (DMZ). It should only talk to internet IPs.
  If the validator tool shows it cannot reach its Nimbus metrics endpoint,
  this could indicate a network connectivity issue in VLAN 4.
- Validator balance should increase by ~0.00012 ETH per epoch (~6.4 minutes)
  when attesting correctly. Monthly expected income: ~0.02 ETH.
```

---

## F. Architecture-Level Recommendations

### 1. Add a correlation pass node to the graph

Current graph: `initialize → [6 fan-out agents] → synthesize`

Proposed: `initialize → [6 fan-out agents] → correlate → synthesize`

The `correlate` node receives all 6 domain summaries, extracts structured signals (suspicious IPs, anomalous devices, failed services), and runs targeted cross-domain lookups:

```python
def correlate(state: DailyReportState) -> dict:
    """Extract structured signals from domain summaries and run cross-domain lookups."""
    # Parse summaries for IP addresses, device names, severity flags
    # For each high-risk IP found by DNS or infrastructure agent:
    #   - call search_logs_by_ip() to get full cross-source context
    #   - call lookup_ip_threat_intel() if not already enriched
    # For any DHCP device flagged as unknown:
    #   - call query_ntopng_host_details() to get flow context
    # Return: correlation_findings dict to merge into synthesis context
```

### 2. Structured domain outputs

Domain agents should return structured JSON rather than freeform markdown. The synthesis agent should receive a schema it can rely on:

```json
{
  "domain": "firewall_threat",
  "severity": "info",
  "findings": [
    {
      "id": "fw_001",
      "severity": "warning",
      "title": "28k port 9000 blocks to validator",
      "detail": "...",
      "ips": ["169.150.222.204", "171.102.145.67"],
      "related_domains": ["validator"],
      "action_required": false
    }
  ],
  "metrics": {
    "total_blocks": 28236,
    "unique_attacker_ips": 10,
    "ssh_failures": 0
  }
}
```

This would allow the correlation pass to programmatically match IPs across domains without relying on LLM natural language comprehension.

### 3. Token budget management

Current token usage per run: ~87,600 tokens. The largest waste is:
- network_flow: 3 calls × 14-18k tokens = 50k+ tokens, of which ~20k are spent paging through flows that produced no findings.
- Wireless: 2 calls × ~900 tokens = near-zero value for 1,800 tokens. (This is fine — the problem is the tool returns nothing useful.)

**Proposed:** Add `agent_type="nano"` or `agent_type="lite"` for simple domains (wireless, validator) that use a smaller/cheaper model. The wireless domain with one tool that returns nothing should not cost the same per-token as the firewall domain with complex multi-source analysis.

### 4. Episodic memory / baseline comparison

As noted in project MEMORY.md, cross-report episodic memory is deferred. But even a minimal implementation would dramatically improve signal quality:

**Minimum viable:** Store these 5 values in Redis after each daily run:
- `dns_queries_yesterday`, `dns_block_rate_yesterday`
- `top_blocked_ips_yesterday` (set of IPs)
- `validator_balance_yesterday`
- `qnap_vol1_used_pct_yesterday`
- `active_dhcp_devices_yesterday` (count)

Then prepend to synthesis prompt: "Yesterday's baseline: DNS {N} queries, {X}% block rate. Validator balance: {B} ETH. QNAP vol: {P}%." This costs ~100 tokens but makes every report meaningfully comparative.

### 5. Validator VLAN firewall rule review (operational finding)

The analysis reveals that pfSense is blocking all inbound TCP/UDP to 192.168.4.2:9000 from WAN. For an Ethereum validator, port 9000 needs to be open inbound for optimal peer discovery. The system is tracking 28,236 blocked inbound connection attempts per day to this port. Consider:
- Adding a pfSense WAN rule: `PASS IN on WAN proto TCP/UDP from any to 192.168.4.2 port 9000`
- This would allow other validators to initiate connections to this node, improving peer count and potentially attestation inclusion timing.

This finding would not have been surfaced without cross-domain correlation between the firewall blocks data and the validator health data.

---

## Summary: Highest-Priority Fixes

In order of impact:

1. **Fix `{hours}` template bug** — currently uncompiled in all 6 domain prompts; affects tool call arguments on non-24h runs.

2. **Add Ethereum validator P2P context to firewall prompt** — prevents 28k+ Ethereum P2P attempts from being misclassified as CRITICAL cross-VLAN attacks every single report.

3. **Prevent speculative flow paging in network_flow agent** — saves ~20k tokens per run and 2 iteration slots from being wasted.

4. **Auto-call `query_qnap_directory_sizes` when volume >85%** — the single most actionable finding in the live run was left half-investigated.

5. **Build UniFi API tools for the wireless domain** — the wireless domain currently produces near-zero signal and wastes iteration budget on a tool that returns empty results.

6. **Add explicit VLAN isolation rules with specific IPs** to the network_flow prompt — "check VLAN traffic" is too vague; the agent needs to know the expected flows for each isolated VLAN.

7. **Add balance delta tracking to validator tool** — current run shows balance but can't say if it went up or down.

8. **Add `query_adguard_blocked_domains_for_client` tool** — essential for investigating high-risk-score clients like bookstack (99% block rate).

9. **Add correlation pass node** — cross-domain IP matching is currently left entirely to the synthesis LLM, which can only work from natural language descriptions.

10. **Add minimal Redis-based baseline comparison** — 5 metrics stored per run enables trend detection and anomaly detection that is currently impossible.
