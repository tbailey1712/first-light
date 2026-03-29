# Architecture Addendum 001 — Open Questions Resolution

**Date:** 2026-03-18
**Applies to:** THREAT_ASSESSMENT_PLAN.md and current agent codebase
**Status:** Authoritative — supersedes any conflicting content in older documents

---

## 1. VLAN Topology Correction (CRITICAL)

The VLAN mapping in several files is wrong. The authoritative layout is:

| VLAN | Subnet | Name | Trust Level | Internet | Cross-VLAN |
|------|--------|------|------------|----------|------------|
| 1 | 192.168.1.x | Main LAN | **Highest** — user computers, workstations | Yes | Outbound to all |
| 2 | 192.168.2.x | IoT Devices | **Low** — smart home devices, cameras, hubs | Yes | Cannot reach VLAN 1 |
| 3 | 192.168.3.x | CCTV | **Isolated** — fully air-gapped segment | **Never** | No WAN, no cross-VLAN ever |
| 4 | 192.168.4.x | DMZ | Ethereum validator | WAN only | Isolated |
| 10 | 192.168.10.x | WiFi Guest | Untrusted | Yes | No cross-VLAN |

There is no VLAN 5.

### Files With Wrong Mappings — Required Fixes

**`agent/graphs/daily_report_graph.py` lines 52-57:**
The `SYNTHESIS_SYSTEM` prompt currently states:
- "VLAN 1: Management — highest trust" → **wrong** (VLAN 1 is Main LAN / user computers)
- "VLAN 2: LAN — trusted user devices" → **wrong** (VLAN 2 is IoT, not trusted)
- "VLAN 5: IoT — untrusted, no cross-VLAN access" → **wrong** (no VLAN 5 exists)

Correct replacement for that block:
```
- VLAN 1 (192.168.1.x): Main LAN — user computers, highest trust
- VLAN 2 (192.168.2.x): IoT Devices — low trust, cannot reach VLAN 1
- VLAN 3 (192.168.3.x): CCTV — fully isolated, no WAN, no cross-VLAN ever
- VLAN 4 (192.168.4.x): DMZ — Ethereum validator, WAN only
- VLAN 10 (192.168.10.x): WiFi Guest — internet only
- ANY traffic from VLAN 3 is CRITICAL (should have zero WAN or cross-VLAN)
- Traffic from VLAN 2 to VLAN 1 is CRITICAL (IoT should never reach trusted LAN)
```

**`agent/prompts/system.py` lines 11-13:**
Currently lists `VLAN 2 (192.168.2.x)` as "IoT/Automation - Smart home devices, servers, IoT" — this is directionally correct but the **trust characterisation matters**. The SigNoz host `192.168.2.106` and QNAP NAS `192.168.2.106` both live on the IoT VLAN, which is a notable network design point. The prompt does not convey that VLAN 2 cannot reach VLAN 1 and should be treated with IoT-level trust.

**`agent/domains/daily_report.py` `FIREWALL_THREAT_SYSTEM` (line 102):**
Correctly identifies Camera VLAN 3 as CRITICAL for cross-VLAN, but does not mention VLAN 2 → VLAN 1 as CRITICAL. Add this case.

**`agent/topology.yaml`:**
The topology file itself is correct in structure but is missing:
- Subnets for VLANs 2, 3, 4, 10 (only VLAN 1 has `subnet` populated)
- The `fully_isolated` flag on VLAN 3 is correct and should be preserved

### Security Logic Changes from Correct VLAN Mapping

The main functional change is in how `192.168.2.x` addresses are scored:

**Before (wrong assumption):** 192.168.2.x = trusted LAN, moderately high trust
**After (correct):** 192.168.2.x = IoT VLAN, low trust — normal to have chatty telemetry, high DNS block rates, unusual outbound patterns

This affects:
- DNS block rate scoring (see Section 6)
- Any firewall finding that attributes a source IP to a VLAN for context
- Cross-VLAN alerts: VLAN 2 → VLAN 1 traffic is a security violation, not just unusual behaviour

---

## 2. IP Hostname Resolution — Shared Utility Design

### Problem

All agents currently surface raw IP addresses in findings. The user requires that every IP presented to the operator be resolved to a hostname before display.

### Implementation: `agent/utils/resolve.py`

This should be a **plain Python utility module**, not a LangChain tool. Agents use it internally before formatting output, not as a tool call.

```python
# agent/utils/resolve.py

import socket
import json
import functools
from typing import Optional

# Module-level LRU cache — persists for process lifetime (reloaded each report run, acceptable)
@functools.lru_cache(maxsize=512)
def resolve_hostname(ip: str) -> str:
    """
    Resolve an IP to its best known hostname.
    Priority order:
      1. topology.yaml known device list (loaded at import time)
      2. ntopng host data (caller must pre-populate _ntopng_names cache)
      3. Reverse DNS (PTR record lookup, 2s timeout)
      4. Raw IP (fallback)

    Returns:
        "hostname (ip)" if a name was found, or just "ip" if not.
    """
    ...

def enrich_ip(ip: str) -> str:
    """Return display string: 'hostname (ip)' or just ip."""
    ...

def prime_ntopng_cache(ntopng_host_data: list[dict]) -> None:
    """
    Pre-populate the ntopng name cache from query_ntopng_active_hosts() output.
    Call this once per report run before any resolve_hostname() calls.

    ntopng host records contain a 'name' field alongside the 'ip' field.
    """
    ...
```

**Lookup chain in detail:**

1. **topology.yaml device list** — load at module import time, index by IP. All devices with known IPs (pfSense `192.168.1.1`, QNAP `192.168.2.106`, validator `192.168.4.2`, etc.) are immediately resolved without a network call.

2. **ntopng active hosts** — `query_ntopng_active_hosts()` returns records with both `ip` and `name` fields. The `network_flow` domain agent already calls this tool. Before that agent formats its output, it should call `prime_ntopng_cache()` with the results. This populates the module-level dict for that run.

3. **Reverse DNS** — `socket.gethostbyaddr(ip)` with a 2-second timeout override via `socket.setdefaulttimeout(2)`. Most internal devices have PTR records through pfSense's DNS resolver. External IPs (attacker IPs) typically will not resolve, which is fine.

4. **Raw IP fallback** — if all three fail, return the raw IP unchanged.

**Caching:** The `lru_cache` on `resolve_hostname` is sufficient for a single report run. For the interactive/Telegram graph, the cache will be warm from prior tool calls in the same process. No Redis needed for hostname cache — the data is ephemeral and cheap to re-derive.

### Integration Points

- Each domain agent's system prompt should instruct: "When reporting IPs, call resolve_hostname(ip) to get the display name"
  — OR, more reliably: domain agents return raw IPs in structured data, and the synthesis agent (or a post-processing step) enriches all IPs before writing the final report.
- The synthesis agent in `daily_report_graph.py` is the natural place to do a final pass: scan the report text for IP patterns (`192\.168\.\d+\.\d+` and external IPs) and replace with resolved names.
- For `agent/prompts/system.py`, the known device table already lists hostname+IP pairs — this serves as a human-readable version of the topology lookup.

---

## 3. Redis Addition

### Confirmed: Add Redis to docker-compose

Add to `/Users/tbailey/Dev/first-light/docker-compose.yml`:

```yaml
redis:
  image: redis:7-alpine
  container_name: fl-redis
  restart: unless-stopped
  command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
  volumes:
    - redis_data:/data
  networks:
    - signoz-net
```

Add `redis_data` to the named volumes block.

### What Goes in Redis

| Key Pattern | Content | TTL | Purpose |
|-------------|---------|-----|---------|
| `tg:conv:{chat_id}` | JSON list of message dicts (last N turns) | 24h | Telegram conversation state for multi-turn interactive mode |
| `tg:session:{chat_id}` | Active graph thread ID | 1h | Resume interrupted conversations |
| `vt:quota:daily` | Integer count | Until midnight UTC | VirusTotal daily API call counter (400 enricher + 100 agent) |
| `vt:cache:{ip_hash}` | JSON enrichment result | 7 days | VT result cache — never re-query same IP within window |
| `report:lock:daily` | "1" | 10 min | Prevent duplicate daily report runs (idempotency) |
| `ntopng:names` | JSON dict {ip: hostname} | 30 min | ntopng resolved names for current run (optional, lru_cache is simpler) |

### LangGraph Checkpointing

The current domain agents use a simple `_run_react_loop()` function, not a compiled LangGraph `StateGraph` with checkpointing. The `agent/graph.py` file uses LangGraph's `MemorySaver`. With Redis now available, migrate `agent/graph.py` to use `langgraph-checkpoint-redis` (or a custom `RedisCheckpointSaver`) so graph state persists across restarts.

```python
# agent/graph.py — updated checkpointer
from langgraph.checkpoint.redis import RedisSaver

checkpointer = RedisSaver.from_conn_string(os.getenv("REDIS_URL", "redis://fl-redis:6379"))
```

The domain agent runners (`daily_report_graph.py`) do not use checkpointing — they run to completion synchronously. Checkpointing is only relevant for the interactive Telegram graph.

---

## 4. Telegram Two-Way Implementation

### Current State

`bot/__init__.py` contains only a version stub. No bot code exists. The architecture calls for `bot/telegram_bot.py` — this file needs to be created from scratch.

### What Needs to Be Built

**Polling vs webhook:** Use **long polling** (`python-telegram-bot` with `Application.run_polling()`). Webhooks require a public HTTPS endpoint; polling works from behind NAT with no infrastructure changes. The agent runs on the internal Docker host, so polling is the right default.

**Required implementation in `bot/telegram_bot.py`:**

```python
# Skeleton — not for copy-paste, illustrates the structure

from telegram.ext import Application, CommandHandler, MessageHandler, filters
from agent.graphs.daily_report_graph import generate_daily_report
from agent.graph import run_interactive_query  # does not exist yet — see below

async def cmd_status(update, context):
    """Quick health check — lightweight, no AI, just tool calls."""
    ...

async def cmd_report(update, context):
    """Trigger full daily report generation on demand."""
    await update.message.reply_text("Generating report, this takes ~60s...")
    report = generate_daily_report(hours=24)
    # Split into chunks ≤4096 chars for Telegram message limit
    for chunk in _split_markdown(report, 4096):
        await update.message.reply_text(chunk, parse_mode="Markdown")

async def handle_message(update, context):
    """Route free-text messages to the interactive agent graph."""
    chat_id = update.effective_chat.id
    if chat_id not in ALLOWED_CHAT_IDS:
        return
    await context.bot.send_chat_action(chat_id, "typing")
    # Load conversation history from Redis
    history = _load_conversation(chat_id)
    response = run_interactive_query(update.message.text, history, chat_id)
    # Save updated history to Redis
    _save_conversation(chat_id, history + [...])
    await update.message.reply_text(response, parse_mode="Markdown")
```

**Interactive graph (`agent/graph.py`):** The existing `agent/graph.py` has a compiled graph but it needs a `run_interactive_query(question, history, thread_id)` entry point that:
- Accepts conversation history (for multi-turn context)
- Uses the Redis checkpointer (thread_id maps to Redis key)
- Has access to all tools (including ntopng, AdGuard, threat intel, QNAP, validator)
- Returns a string response suitable for Telegram

**Security:** Load `TELEGRAM_ALLOWED_CHAT_IDS` from `.env` as a comma-separated list. Reject all messages from unlisted chat IDs silently.

**Message length:** Telegram has a 4096-character limit per message. The `generate_daily_report()` output easily exceeds this. Implement `_split_markdown(text, max_len)` that splits on paragraph boundaries (`\n\n`) rather than mid-sentence.

**Typing indicator:** Call `send_chat_action(chat_id, ChatAction.TYPING)` before invoking the agent. For long operations, re-send every 4 seconds in a background task (Telegram typing indicators expire after 5 seconds).

---

## 5. QNAP Storage Advisor — Directory-Level Analysis

### Confirmed: QNAP API is Already Configured

The `fl-qnap-api-exporter` Prometheus exporter (`agent/tools/qnap_tools.py`) is operational. The existing `query_qnap_health()` tool provides volume-level disk usage. The user confirms the QNAP API is available for directory-level analysis.

### QNAP File Station API for Directory Analysis

The QNAP File Station API provides folder size information:

```
GET http://<nas-ip>:8080/cgi-bin/filemanager/utilRequest.cgi
    ?func=get_tree
    &path=/share/CACHEDEV1_DATA
    &tree_type=folder_size
    &sid=<session_id>
```

Authentication uses QNAP's session-based auth:
```
POST http://<nas-ip>:8080/cgi-bin/authLogin.cgi
     ?user=<username>&passwd=<md5_password>
```

**New tool to add: `query_qnap_directory_sizes(path: str, depth: int = 2) -> str`**

This tool should:
1. Authenticate via `authLogin.cgi` (store session token; reuse within a run)
2. Call `get_tree` or `get_folder_size` for the given path
3. Return top-N subdirectories by size for the storage advisor to surface

The storage advisor agent (`run_infrastructure_agent`) can then identify which specific share or subdirectory is consuming unexpected space — e.g., "CACHEDEV1_DATA/homes/tbailey/Downloads is 847 GB and grew 12 GB yesterday" rather than just "volume DataVol1 is at 73% capacity."

**Credentials:** Add `QNAP_API_URL`, `QNAP_API_USER`, `QNAP_API_PASS` to `.env` and `agent/config.py`. The exporter already has credentials — reuse the same user.

---

## 6. Revised Security Scoring — VLAN Context

The triage scoring in domain agent prompts and `agent/prompts/system.py` must account for VLAN trust level when evaluating events. The current scoring rules treat `192.168.2.x` and `192.168.1.x` symmetrically in most places. They should not be.

### Updated Scoring Rubric

**DNS Block Rate (AdGuard)**

| Device / VLAN | High block rate | Interpretation |
|---------------|----------------|----------------|
| VLAN 1 (192.168.1.x) user device >50% | HIGH severity | Unusual for trusted device — investigate |
| VLAN 2 (192.168.2.x) IoT device >80% | LOW/INFO | Expected for IoT telemetry — contextualise only |
| VLAN 2 (192.168.2.x) IoT device with C2/DGA domains | CRITICAL | Domain type matters more than rate |
| VLAN 3 (192.168.3.x) ANY query | WARNING | CCTV should not be generating external DNS |
| VLAN 4 (192.168.4.x) non-Ethereum domains | WARNING | Validator should only contact beacon/execution peers |

The existing adjustments in `agent/prompts/system.py` (Roku -70 pts, IoT hubs -40 pts) are correct in spirit but the VLAN 2 label is wrong. Roku (`192.168.2.60`) and Hue (`192.168.2.44`) are correctly identified as IoT by device name — the risk adjustment is appropriate. The gap is that the system prompt describes VLAN 2 as "IoT/Automation" without conveying it has **lower trust than VLAN 1 and cannot see VLAN 1**.

**Firewall Blocks — VLAN Source Context**

| Source VLAN | Target | Severity |
|-------------|--------|----------|
| External → Any | Blocked at WAN | INFO (normal scanning noise) |
| VLAN 2 (IoT) → VLAN 1 (trusted LAN) | Any | **CRITICAL** — IoT should never reach trusted LAN |
| VLAN 3 (CCTV) → Any | Any | **CRITICAL** — CCTV is fully isolated |
| VLAN 4 (DMZ) → VLAN 1 or 2 | Any | **CRITICAL** — validator should not contact internal VLANs |
| VLAN 1 → VLAN 2 | Blocked | WARNING — trusted device hitting IoT firewall rules |
| VLAN 10 (Guest) → Any internal | Any | **CRITICAL** — guest isolation violation |

**ntopng Alerts — VLAN Context**

ntopng sees traffic across all VLANs. When it surfaces an alert involving a `192.168.2.x` source, the agent must not treat it with trusted-LAN weight. Add to `FIREWALL_THREAT_SYSTEM`:

```
VLAN trust levels for ntopng findings:
- 192.168.1.x: Trusted LAN — any anomaly is HIGH priority
- 192.168.2.x: IoT VLAN — high DNS blocks normal; cross-VLAN attempts are CRITICAL
- 192.168.3.x: CCTV — any traffic outside subnet is CRITICAL
- 192.168.4.x: DMZ — lateral movement to internal VLANs is CRITICAL
- 192.168.10.x: Guest — any non-internet traffic is CRITICAL
```

**Specific Correction Needed in `agent/prompts/system.py`:**

`SigNoz` at `192.168.2.106` and QNAP NAS at `192.168.2.106` (same IP — SigNoz runs on the QNAP/Docker host) are on VLAN 2. The agent must not treat these as untrusted IoT devices. Add explicit infrastructure exceptions:

```yaml
# In topology.yaml — add trust_override to specific VLAN 2 devices
- ip: 192.168.2.106
  hostname: docker.mcducklabs.com / nas.mcducklabs.com
  vlan: 2
  role: infrastructure
  trust_override: high  # These are operator-managed infrastructure, not IoT
```

And document in the system prompt: "Infrastructure hosts on VLAN 2 (docker.mcducklabs.com 192.168.2.106) are trusted regardless of VLAN — high traffic from this IP to VLAN 1 is expected backup/monitoring traffic."

---

## 7. Defaults for Unanswered Questions

The following defaults apply where the user did not provide explicit guidance:

| Question | Default Applied |
|----------|----------------|
| VT quota split | 400 calls/day for enricher background tasks, 100 calls/day reserved for agent tool use |
| VT in interactive mode | No VT lookups in interactive Telegram queries unless user explicitly asks "check this IP on VirusTotal" |
| AdGuard per-device query limit | 500 queries per device when fetching per-client query logs (prevent timeout on chatty IoT devices) |
| CrowdSec surfacing | Surface CrowdSec block events when they correlate with pfSense firewall data (same IP within same time window) — do not surface CrowdSec-only events as standalone findings |
| Weekly/monthly reports | Leave as placeholder — implement after daily reports are stable |

---

## 8. Summary of Required Code Changes

In priority order:

1. **Fix VLAN map in `agent/graphs/daily_report_graph.py`** (`SYNTHESIS_SYSTEM` lines 52-57) — wrong VLAN labels affect every synthesized report today.

2. **Fix VLAN map in `agent/prompts/system.py`** — update VLAN 2 description to make clear it is IoT (low trust), not a trusted device VLAN.

3. **Add `agent/utils/resolve.py`** — hostname resolution utility with topology + ntopng + PTR lookup chain.

4. **Add Redis to `docker-compose.yml`** — `redis:7-alpine`, 256 MB, named volume.

5. **Create `bot/telegram_bot.py`** — polling-based bot with `/status`, `/report`, free-text to interactive graph.

6. **Add `run_interactive_query()` to `agent/graph.py`** — entry point for Telegram handler with Redis checkpointing.

7. **Add `query_qnap_directory_sizes()` to `agent/tools/qnap_tools.py`** — File Station API for directory-level analysis.

8. **Update `agent/topology.yaml`** — add subnets for VLANs 2, 3, 4, 10; add `trust_override` for infrastructure hosts on VLAN 2.
