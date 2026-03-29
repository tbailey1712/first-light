# First Light AI — Engineering Epic: Stabilize, Complete, and Extend

**Epic ID:** FL-EPIC-001
**Status:** Ready for Sprint Planning
**Author:** Principal Engineer
**Date:** 2026-03-28

---

## 1. Epic Overview

### Goal

Transform First Light from a working-but-fragile daily report pipeline into a fully production-hardened, interactively queryable home network observability platform. The system currently produces daily reports via a six-domain LangGraph pipeline and delivers them one-way to Telegram. This Epic completes the platform by: removing all dead and broken code that creates maintenance liability, hardening the live pipeline against known bugs and security vulnerabilities, and delivering a two-way Telegram bot that lets the owner ask ad-hoc questions against live network data.

### Success Criteria

1. `docker-compose up` starts all services without build errors (threat-intel-enricher directory exists and builds).
2. The daily report runs end-to-end without Python warnings about deprecated APIs or silent parameter drops.
3. No SQL injection vectors exist in any ClickHouse query path.
4. DNS resolution within agent tool calls never blocks for more than 2 seconds per IP.
5. The Telegram bot responds to `/status`, `/report`, `/ask <question>`, and free-text within 30 seconds; all other chat IDs are silently rejected.
6. Conversation state persists across bot restarts via Redis.
7. The duplicate-report-run guard prevents two simultaneous daily reports.
8. `scripts/test_integration.py` passes all scenarios against a live stack.

### Definition of "Done" for the Full Epic

- All Sprint 1 bugs fixed and verified by unit tests.
- All dead code files deleted (not commented out).
- All Sprint 2 infrastructure in place: topology.yaml complete, resolve.py fully implemented, Redis running in compose, `query_qnap_directory_sizes` implemented.
- Sprint 3 bot running in production: `bot/telegram_bot.py` service live in compose, all commands functional, Redis conversation history working.
- `scripts/test_integration.py` green against the live stack.
- No `datetime.utcnow()`, bare `except:`, or hardcoded credential strings remain in the codebase.

---

## 2. Sprint 1 — Stabilize

**Goal:** Fix all known bugs, remove all dead code, and ensure the existing daily report pipeline is solid. No new features. Every ticket here is a prerequisite for Sprints 2 and 3.

**Duration target:** 1 week

---

### S1-01: Fix hardcoded URLs in validator.py

**File:** `/Users/tbailey/Dev/first-light/agent/tools/validator.py`

**Description:** Lines 17–18 define `NIMBUS_URL` and `NETHERMIND_URL` as hardcoded string literals. Every other tool reads its endpoint from `get_config()`. When the validator moves or the config changes, only this file will be out of sync. The `config.py` already has `validator_host` and `consensus_metrics_port` / `execution_metrics_port` fields.

**Change:**

Replace the module-level literals with a lazy accessor pattern:

```python
def _get_nimbus_url() -> str:
    cfg = get_config()
    host = cfg.validator_host or "vldtr.mcducklabs.com"
    return f"http://{host}:{cfg.consensus_metrics_port}/metrics"

def _get_nethermind_url() -> str:
    cfg = get_config()
    host = cfg.validator_host or "vldtr.mcducklabs.com"
    return f"http://{host}:{cfg.execution_metrics_port}/metrics"
```

Call `_get_nimbus_url()` at the top of `query_validator_health` and `_get_nethermind_url()` for the execution section. Remove the two module-level constants entirely.

**Acceptance criteria:**
- `NIMBUS_URL` and `NETHERMIND_URL` constants no longer exist in the file.
- Setting `VALIDATOR_HOST=test-host` in `.env` changes the URL used by the tool (verifiable via unit test with monkeypatched `get_config()`).
- `query_validator_health` still calls `httpx.Client(timeout=10.0)` and returns valid JSON on success.

---

### S1-02: Add timeout to socket.gethostbyaddr in resolve.py

**File:** `/Users/tbailey/Dev/first-light/agent/utils/resolve.py`

**Description:** `resolve_hostname()` calls `socket.gethostbyaddr(ip)` with no timeout. On a home network with a mix of devices, many IPs will not resolve reverse DNS. The default system timeout can be 15–30 seconds. The `enrich_ip_column()` function in `metrics.py` calls `resolve_hostname()` for every private IP in AdGuard query results — up to 20 lookups per tool call. This directly stalls the ReAct loop.

**Change:**

Wrap the call in a `socket.setdefaulttimeout(2)` context. Because `setdefaulttimeout` is global and not thread-safe for the existing `@lru_cache` pattern, use a threading approach:

```python
import socket
import concurrent.futures

_dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns-resolve")

@lru_cache(maxsize=512)
def resolve_hostname(ip: str) -> str:
    ...
    try:
        future = _dns_executor.submit(socket.gethostbyaddr, ip)
        hostname, _, _ = future.result(timeout=2.0)
        ...
    except (concurrent.futures.TimeoutError, socket.herror, socket.gaierror, OSError):
        return ip
```

This isolates the blocking socket call to a dedicated thread pool and enforces a hard 2-second per-IP ceiling without disturbing any other socket state.

**Acceptance criteria:**
- A unit test that calls `resolve_hostname("192.0.2.255")` (TEST-NET, guaranteed non-resolving) completes in under 3 seconds.
- The `@lru_cache` still caches results: calling the same IP twice executes `gethostbyaddr` only once (verifiable by mock).
- The executor thread pool is a module-level singleton (not recreated per call).

---

### S1-03: Fix deprecated datetime.utcnow() calls

**File:** `/Users/tbailey/Dev/first-light/agent/graphs/daily_report_graph.py` (lines 296, 322, 347, 354)

**Description:** `datetime.utcnow()` is deprecated as of Python 3.12 and raises a `DeprecationWarning` that will become an error in a future minor release. The validator tool already uses `datetime.now(timezone.utc)` which is the correct pattern.

**Change:** Replace every `datetime.utcnow()` call with `datetime.now(timezone.utc)`. Ensure `timezone` is imported from `datetime`. Also fix the same pattern in `/Users/tbailey/Dev/first-light/agent/state.py` (line 28: `default_factory=datetime.utcnow`) and the `_format_timestamp` helper in `/Users/tbailey/Dev/first-light/agent/tools/logs.py` (line 467: `datetime.utcfromtimestamp`).

**Acceptance criteria:**
- Running `python -W error::DeprecationWarning -c "from agent.graphs.daily_report_graph import generate_daily_report"` produces no warnings.
- Running `python -W error::DeprecationWarning -c "from agent.state import Finding"` produces no warnings.
- All timestamp strings produced by the daily report remain ISO 8601 UTC format.

---

### S1-04: Fix bare except in logs.py

**File:** `/Users/tbailey/Dev/first-light/agent/tools/logs.py` (line 466)

**Description:** The `_format_timestamp` function has a bare `except:` clause. This catches `KeyboardInterrupt`, `SystemExit`, and `GeneratorExit` — all of which should propagate up. A bare except that catches `KeyboardInterrupt` inside a long agent run means Ctrl+C won't stop the process cleanly.

**Change:** Replace `except:` with `except Exception:`.

**Acceptance criteria:**
- No bare `except:` clause exists anywhere in `logs.py` (verify with `ruff check --select E722`).
- `KeyboardInterrupt` raised inside `_format_timestamp` propagates out of the function (unit testable via mock).

---

### S1-05: Fix ModelName Literal — remove hallucinated model IDs

**File:** `/Users/tbailey/Dev/first-light/agent/model_config.py` (lines 13–33)

**Description:** The `ModelName` Literal type includes model IDs that do not exist: `gpt-5.2`, `gpt-5.2-pro`, `gemini/gemini-3.1-pro-preview`, `gemini/gemini-3-pro-preview`, `gemini/gemini-3-flash-preview`. When any of these is set as the value of `MICRO_AGENT_MODEL`, `SUPERVISOR_MODEL`, etc., Pydantic's field validation rejects the config at startup with a `ValidationError` referencing "value is not a valid enumeration member". This prevents deploying any model outside the hardcoded list without a code change.

**Change:** The `ModelName` Literal should contain only model IDs that are known to exist and route correctly through the LiteLLM proxy. Remove the five fictitious IDs. The correct current set is:

```python
ModelName = Literal[
    "claude-opus-4-6",
    "claude-opus-4-5",
    "claude-sonnet-4-6",
    "claude-sonnet-4-5",
    "claude-haiku-4-5",
    "gpt-4o",
    "gpt-4o-mini",
    "gemini/gemini-2.0-flash",
    "gemini/gemini-1.5-pro",
    "openrouter/x-ai/grok-3",
]
```

This list should be treated as a documentation artifact of which models the LiteLLM proxy has been configured to route. If new models are added to the proxy, this list is updated as part of that configuration work — not speculatively in advance.

**Acceptance criteria:**
- `python -c "from agent.model_config import ModelName"` imports without error.
- Setting `MICRO_AGENT_MODEL=gpt-5.2` and calling `get_model_config()` raises `ValidationError` (the fake ID is gone from the Literal, so Pydantic rejects it).
- Setting `MICRO_AGENT_MODEL=gpt-4o` and calling `get_model_config()` succeeds.

---

### S1-06: Fix dual Langfuse client instantiation

**File:** `/Users/tbailey/Dev/first-light/agent/langfuse_integration.py`

**Description:** `langfuse_integration.py` imports `Langfuse` and instantiates it via `Langfuse(secret_key=..., public_key=..., host=...)` (the v2 SDK pattern). `llm.py` uses `from langfuse import get_client as get_langfuse_client` which is the v4 OTel singleton. These are two incompatible client instances. Any trace data emitted by `langfuse_integration.py` (e.g., via `PromptManager`) does not flow into the same trace as calls made through `llm.py`. The `@observe` decorators in `llm.py` create OTel spans; the `Langfuse()` instance in `langfuse_integration.py` uses a legacy SDK path that creates separate, unlinked traces.

**Change:** In `langfuse_integration.py`, replace the `Langfuse(...)` constructor with `get_client()` from the new API:

```python
from langfuse import get_client, observe

@lru_cache(maxsize=1)
def get_langfuse_client():
    # Validate env vars first (keep existing validation logic)
    ...
    return get_client()
```

The `PromptManager` class uses `self.client.get_prompt(...)` and `self.client.create_prompt(...)` — verify these methods exist on the v4 `get_client()` return type. If the v4 client has a different prompt API, adapt the calls accordingly. The `trace_agent` decorator uses `@observe` which is already v4-compatible and needs no change.

**Acceptance criteria:**
- `from agent.langfuse_integration import get_langfuse_client; from agent.llm import chat` — both can be imported in the same process without conflict.
- A call to `get_agent_prompt_with_fallback("test-prompt", "fallback")` does not raise any SDK version mismatch exception.
- There is exactly one Langfuse client construction pattern in the codebase (grep for `Langfuse(` should return zero results after this change).

---

### S1-07: Fix SQL injection in ClickHouse queries

**Files:**
- `/Users/tbailey/Dev/first-light/agent/tools/logs.py` (line 399, function `search_logs_by_ip`)
- `/Users/tbailey/Dev/first-light/agent/tools/threat_intel_tools.py` (line 204, `lookup_ip_threat_intel`, and line 220, same function)

**Description:** Both functions interpolate `ip_address` directly into ClickHouse SQL via f-strings. An attacker who controls network traffic labels (e.g., a device that registers a crafted hostname that gets stored as an IP attribute) could inject arbitrary SQL. More practically, if the LLM hallucinates or is prompted to call these tools with malicious arguments, the query executes with arbitrary SQL. This is a security vulnerability in a security product.

**Change:** ClickHouse's HTTP interface supports query parameters via `{param_name:Type}` syntax. Refactor both functions to use parameterized queries:

```python
query = """
SELECT ...
FROM signoz_logs.logs_v2
WHERE ...
  AND attributes_string['pfsense.src_ip'] = {ip_address:String}
"""
params = {"ip_address": ip_address, "hours": hours}

# Pass params to _execute_clickhouse_query
response = client.post(
    clickhouse_url,
    params={
        "user": ...,
        "password": ...,
        "query": query,
        "param_ip_address": ip_address,
        "param_hours": hours,
    }
)
```

ClickHouse HTTP accepts `param_<name>` query parameters that substitute into `{name:Type}` placeholders. The `LIKE '%{ip_address}%'` pattern cannot be parameterized in the same way — replace it with `positionCaseInsensitive(body, {ip_address:String}) > 0`.

Also add IP address validation at the function entry point: `ip_address` must match `^\d{1,3}(\.\d{1,3}){3}$` before the query is constructed, raising `ValueError` otherwise.

**Acceptance criteria:**
- `search_logs_by_ip("'; DROP TABLE logs_v2; --", 24)` does not execute the injected SQL (it either fails validation or the injection is treated as a literal string value, verifiable by inspecting the generated query string).
- `search_logs_by_ip("not-an-ip", 24)` raises `ValueError` with a descriptive message.
- Existing functionality: `search_logs_by_ip("192.168.1.1", 24)` still returns valid JSON.

---

### S1-08: Remove dead config field litellm_model

**File:** `/Users/tbailey/Dev/first-light/agent/config.py` (line 82)

**Description:** `litellm_model: str = "claude-sonnet-4-5-20250929"` in `FirstLightConfig` is declared but never read by anything in the active pipeline. `llm.py` reads model selection exclusively from `model_config.py` via environment variables. The field in `config.py` creates a false impression that changing it affects model selection. `agent/graph.py` line 131 does reference `config.litellm_model` — this is the legacy `create_agent()` function that is itself dead code (never called), but it creates confusion.

**Change:** Remove the `litellm_model` field from `FirstLightConfig`. Remove `create_agent()`, `get_agent()`, and `_agent` from `agent/graph.py` since that entire file's runtime logic is dead — `graph.py` will be repurposed in Sprint 3 for `run_interactive_query()`.

Note: `graph.py` still imports tools and defines `create_system_prompt()`. Preserve `create_system_prompt()` as it will be reused in Sprint 3.

**Acceptance criteria:**
- `FirstLightConfig` has no `litellm_model` field.
- `grep -r "litellm_model" agent/` returns zero results (except the `model_config.py` field `litellm_base_url` and `litellm_api_key` which are different and correct).
- `agent/graph.py` no longer contains `create_agent()` or `get_agent()`.
- `python -c "from agent.config import get_config; c = get_config()"` still succeeds.

---

### S1-09: Fix run_network_flow_agent ignoring hours parameter

**File:** `/Users/tbailey/Dev/first-light/agent/domains/daily_report.py` (line 198, function `run_network_flow_agent`)

**Description:** The function signature is `run_network_flow_agent(hours: int = 24, ...)` but the `user` prompt variable is set to `NETWORK_FLOW_USER` (a module-level constant) without substituting `hours`. All other domain agents either embed the hours value into their user prompt or pass it to tools. As a result, if the daily report is ever run with a non-24-hour window (the graph supports this via `generate_daily_report(hours=N)`), the network flow agent always analyzes "the past 24 hours."

**Change:** Modify `NETWORK_FLOW_USER` to be either a format string template or generate the user prompt inline:

```python
user = f"Analyze network flow data for the past {hours} hours. ..."
```

Match whatever pattern the other domain agents use (inspect `run_firewall_threat_agent` as the reference).

**Acceptance criteria:**
- Calling `run_network_flow_agent(hours=6, ...)` produces a user prompt string containing "6" (verifiable via unit test with mocked `run_react_loop`).
- Calling `run_network_flow_agent(hours=24, ...)` still works correctly.

---

### S1-10: Cap enrich_ip_column DNS lookup count in metrics.py

**File:** `/Users/tbailey/Dev/first-light/agent/tools/metrics.py` (line 200)

**Description:** `enrich_ip_column(result)` is called on the raw string output of AdGuard queries. The function calls `resolve_hostname()` for every distinct private IP in the result text. An AdGuard query result listing top-N clients can contain 20+ distinct IPs. Even with a 2-second timeout per lookup (after S1-02), 20 sequential lookups add 40 seconds in the worst case. The timeout fix from S1-02 mitigates hanging, but the volume problem remains.

**Change:** Add an optional `max_lookups: int = 10` parameter to `enrich_ip_column()` in `agent/utils/resolve.py`. When the number of distinct IPs found exceeds `max_lookups`, enrich the first `max_lookups` IPs and leave the remainder as raw IPs. Add a note to the returned string when truncation occurs: append a line `(+ N IPs not resolved — limit reached)`. The caller in `metrics.py` does not need to change; the default limit applies automatically.

**Acceptance criteria:**
- A unit test with a mock input string containing 25 distinct private IPs verifies that `resolve_hostname` is called at most 10 times.
- A result containing exactly 8 distinct IPs still enriches all 8 (no premature truncation).
- The truncation notice string is present in output when the limit is exceeded.

---

### S1-11: Remove dead code — Stack B files

**Files to delete:**
- `/Users/tbailey/Dev/first-light/agent/graphs/dns_security_graph.py`
- `/Users/tbailey/Dev/first-light/agent/domains/dns_security.py`
- `/Users/tbailey/Dev/first-light/agent/state.py`
- `/Users/tbailey/Dev/first-light/agent/agent_factory.py`
- `/Users/tbailey/Dev/first-light/agent/tools/threat_intel.py`
- `/Users/tbailey/Dev/first-light/agent/reports/database.py`

**Description:** These six files constitute "Stack B" — an abandoned hierarchical multi-agent architecture that was superseded by the current LangGraph fan-out pipeline. None are imported by any file in the active execution path. `dns_security_graph.py` uses `AgentState` (from the deleted `state.py`) instead of `DailyReportState`, so it would crash on import. `agent_factory.py` has empty registries and always falls through to generic agents. `database.py` implements a SQLite trend DB that is never instantiated.

Keeping dead code creates cognitive overhead for any developer reading the codebase, and the `AgentState` / `MicroAgentInput` / `Finding` types can cause confusion when someone tries to understand what state types the live pipeline uses.

**Acceptance criteria:**
- None of the six files exist in the repository.
- `python -c "from agent.graphs.daily_report_graph import generate_daily_report"` succeeds (no broken imports from the deleted files).
- `python -c "from agent.scheduler import main"` succeeds.
- `grep -r "from agent.state import" agent/` returns zero results.
- `grep -r "from agent.agent_factory import" agent/` returns zero results.

---

### S1-12: Fix missing threat-intel-enricher service directory

**File:** `/Users/tbailey/Dev/first-light/docker-compose.yml` and `/Users/tbailey/Dev/first-light/services/threat-intel-enricher/`

**Description:** `docker-compose.yml` line 171 references `build: ./services/threat-intel-enricher`. The directory already exists (it was found at `services/threat-intel-enricher/` with `Dockerfile`, `enricher.py`, `README.md`, `requirements.txt`), so the compose reference is correct. However, running `docker-compose build threat-intel-enricher` should be tested and any build failures resolved. This ticket is a verification-and-fix ticket rather than a code ticket.

**Change:** Run `docker-compose build threat-intel-enricher` and resolve any build failures. Common issues to check: Python version in Dockerfile matches `requirements.txt` constraints, base image exists, all `import` statements in `enricher.py` have corresponding `requirements.txt` entries.

**Acceptance criteria:**
- `docker-compose build threat-intel-enricher` exits 0.
- `docker-compose up -d threat-intel-enricher` starts the container and it transitions to healthy state within 90 seconds.
- `curl http://localhost:9006/` returns a Prometheus metrics response.

---

### Sprint 1 — Dependencies

All S1 tickets are independent of each other with one exception: S1-11 (delete dead code) should be done after S1-06 (Langfuse client fix) because `agent_factory.py` imports from `langfuse_integration.py` — fixing the import there first makes it easier to verify S1-11 doesn't break anything.

Suggested order: S1-03, S1-04, S1-07, S1-02, S1-10, S1-01, S1-09, S1-05, S1-06, S1-08, S1-11, S1-12.

---

## 3. Sprint 2 — Foundation

**Goal:** Complete the infrastructure layer that Sprints 1 and 3 depend on. Topology accuracy, full resolve.py implementation, Redis service, and the missing QNAP directory sizes tool. No user-facing features yet.

**Duration target:** 1 week (can overlap with Sprint 1 tail)

---

### S2-01: Complete topology.yaml — subnets and trust overrides

**File:** `/Users/tbailey/Dev/first-light/agent/topology.yaml`

**Description:** The VLANs block is missing `subnet` fields for VLANs 2, 3, 4, and 10. The resolve.py spec requires the topology to be indexed by IP so VLAN membership can be determined from an address. VLAN 2 IoT also lacks `trust_level` context — VLAN 2 is "restricted" but the NAS at `192.168.2.106` is a trusted infrastructure host that should not be flagged by security analysis. The `fully_isolated: true` flag on VLAN 3 (cameras) is correct and must be preserved.

**Change:**

Add `subnet` to all VLANs lacking it:

```yaml
- id: 2
  name: "IoT"
  subnet: "192.168.2.0/24"
  trust_level: "low"
  ...

- id: 3
  name: "Cameras"
  subnet: "192.168.3.0/24"
  fully_isolated: true
  ...

- id: 4
  name: "DMZ"
  subnet: "192.168.4.0/24"
  ...

- id: 10
  name: "Guest"
  subnet: "192.168.10.0/24"
  ...
```

Add `trust_override: high` to the `storage` device entry:

```yaml
storage:
  ...
  ip: "192.168.2.106"
  trust_override: high
  trust_reason: "Infrastructure NAS — docker.mcducklabs.com / nas.mcducklabs.com"
```

**Acceptance criteria:**
- `load_topology()["network"]["vlans"]` — all five VLAN entries have a `subnet` key.
- VLAN 3's `fully_isolated: true` is still present.
- `load_topology()["devices"]["storage"]["trust_override"] == "high"`.
- `python -c "from agent.config import load_topology; t = load_topology(); print(t)"` prints without error.

---

### S2-02: Rewrite resolve.py with full lookup chain

**File:** `/Users/tbailey/Dev/first-light/agent/utils/resolve.py`

**Description:** Current `resolve.py` only does reverse DNS. The full spec requires a three-tier lookup chain: topology.yaml device list first (zero latency, always accurate for known infrastructure), then an ntopng active hosts cache (populated once per report run), then reverse DNS with 2-second timeout, then raw IP fallback.

**Implementation spec:**

```python
# Module-level state
_topology_index: dict[str, str] = {}   # ip -> hostname, loaded at import
_ntopng_cache: dict[str, str] = {}     # ip -> hostname, populated by prime_ntopng_cache()

def _load_topology_index() -> dict[str, str]:
    """Index all known devices from topology.yaml by IP address."""
    ...

def prime_ntopng_cache(host_data: list[dict]) -> None:
    """
    Pre-populate the module-level ntopng cache from active host data.
    
    Call this once at the start of a report run with the output of
    query_ntopng_active_hosts(). Clears the previous cache before loading.
    
    Args:
        host_data: List of dicts with at minimum 'ip' and 'name' keys.
    """
    global _ntopng_cache
    _ntopng_cache = {}
    for host in host_data:
        ip = host.get("ip") or host.get("ip_address")
        name = host.get("name") or host.get("hostname")
        if ip and name and name != ip:
            _ntopng_cache[ip] = name

@lru_cache(maxsize=512)
def resolve_hostname(ip: str) -> str:
    """
    Resolve IP → hostname using four-tier lookup chain.
    Returns 'hostname (ip)' format if resolved, else raw ip.
    
    Lookup order:
    1. topology.yaml device index (zero latency)
    2. ntopng active hosts cache (populated by prime_ntopng_cache())
    3. Reverse DNS with 2-second timeout via thread executor
    4. Raw IP fallback
    """
    ...

def enrich_ip_column(text: str, max_lookups: int = 10) -> str:
    """Post-process text replacing bare private IPs with 'hostname (ip)' format."""
    ...
```

The `_topology_index` is populated at module import time by calling `_load_topology_index()`. This indexes the `devices` section of `topology.yaml` by the `ip` field where present, and also parses device hostnames (e.g., `"nas.mcducklabs.com"` → alias `"192.168.2.106"`).

The return format contract: if a name is found, return `f"{name} ({ip})"`. If no name is found, return the raw IP string. This contract is what `enrich_ip_column` builds on: it substitutes bare IPs with the resolved form.

**Acceptance criteria:**
- `prime_ntopng_cache([{"ip": "192.168.2.100", "name": "my-device"}])` then `resolve_hostname("192.168.2.100")` returns `"my-device (192.168.2.100)"`.
- `resolve_hostname("192.168.2.106")` returns `"nas (192.168.2.106)"` (from topology index, without a network call).
- An IP not in topology or ntopng cache, with no reverse DNS, returns the raw IP within 3 seconds (timeout works).
- `_topology_index` is populated at module import without any explicit init call.
- `lru_cache` still works: calling `resolve_hostname("192.168.2.106")` twice only hits the topology index once (verifiable by clearing the lru_cache between calls in a unit test).

---

### S2-03: Add Redis service to docker-compose.yml

**File:** `/Users/tbailey/Dev/first-light/docker-compose.yml`

**Description:** `requirements.txt` has `redis>=5.0`. The bot (Sprint 3) will use Redis for conversation history and the daily report will use it for a distributed lock. Redis must be available in the compose stack before the bot service can be wired in.

**Change:** Add the Redis service and volume per the spec:

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
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
    interval: 30s
    timeout: 5s
    retries: 3
```

Add `redis_data:` to the `volumes:` section with `name: fl-redis-data`.

Add `redis` to the `depends_on` list of the `agent` service (the scheduler will use it for the report lock in Sprint 3).

**Acceptance criteria:**
- `docker-compose up -d redis` starts without error.
- `docker-compose exec redis redis-cli ping` returns `PONG`.
- `docker-compose exec redis redis-cli info memory | grep maxmemory:` returns `262144000` (256 MB in bytes).
- The `agent` service's `depends_on` list includes `redis`.

---

### S2-04: Add Redis report lock to scheduler.py

**File:** `/Users/tbailey/Dev/first-light/agent/scheduler.py`

**Description:** The scheduler uses APScheduler with `max_instances=1`, which prevents the same APScheduler job from being queued twice within a single process. However, if the container is restarted mid-run (e.g., during a deploy), a new instance starts and immediately runs the report again if the restart happens within the scheduled window. The Redis lock provides a distributed guard: only one process can hold the lock at a time, with a 10-minute TTL.

**Change:**

Add a `get_redis_client()` helper that reads `REDIS_URL` from the environment (default `redis://fl-redis:6379/0`) and returns a `redis.Redis` instance.

Wrap the `run_daily_report` body with a lock acquisition:

```python
async def run_daily_report():
    r = get_redis_client()
    acquired = r.set("report:lock:daily", "1", nx=True, ex=600)
    if not acquired:
        logger.warning("Daily report already running (Redis lock held) — skipping")
        return
    try:
        ...  # existing report generation
    finally:
        r.delete("report:lock:daily")
```

**Acceptance criteria:**
- If Redis is unavailable (connection refused), the scheduler logs a warning and falls back to running the report anyway (the lock is best-effort, not blocking). Implement this by catching `redis.exceptions.ConnectionError` and logging.
- If the lock is held, `run_daily_report()` returns immediately after logging the skip message (unit testable by mocking `r.set` to return `None`).
- The lock TTL is 10 minutes (600 seconds), verifiable by inspecting the `ex=600` argument in code.

---

### S2-05: Implement query_qnap_directory_sizes

**File:** `/Users/tbailey/Dev/first-light/agent/tools/qnap_tools.py`

**Description:** The Architecture Addendum calls for a `query_qnap_directory_sizes()` tool using the QNAP File Station API. This is needed because the existing `query_qnap_health()` tool reports aggregate volume utilization (e.g., "Volume1 is 73% full") but cannot tell the agent which directories are consuming space. When a NAS is filling up, the actionable question is "what's using the space?"

**Implementation spec:**

```python
@tool
def query_qnap_directory_sizes(path: str = "/share/CACHEDEV1_DATA", top_n: int = 10) -> str:
    """
    List the largest subdirectories under a given NAS path.
    
    Uses the QNAP File Station API: authenticates, then calls get_tree with
    tree_type=folder_size to retrieve directory size data.
    
    Args:
        path: NAS path to analyze (default: primary data volume root)
        top_n: Number of largest subdirectories to return (default: 10)
    
    Returns:
        JSON list of {name, path, size_gb, size_bytes} sorted by size descending.
    """
```

Authentication flow:
1. POST to `{QNAP_API_URL}/cgi-bin/authLogin.cgi` with `user=` and `passwd=` (MD5 hashed, or check QNAP's API for current auth method).
2. Extract `authSid` from the XML or JSON response.
3. GET `{QNAP_API_URL}/cgi-bin/filemanager/utilRequest.cgi?func=get_tree&path={path}&tree_type=folder_size&sid={authSid}`.
4. Parse response and return top-N by size.

Credentials come from `get_config()`. Add to `FirstLightConfig` in `config.py`:

```python
qnap_api_url: Optional[str] = None
qnap_api_user: Optional[str] = None
qnap_api_pass: Optional[str] = None
```

Session token reuse: use a module-level `_qnap_sid: Optional[str] = None` with `_qnap_sid_expiry: Optional[float] = None`. Cache the session token for 50 minutes (QNAP sessions expire at 60 minutes). On `authLogin.cgi` call, set the expiry to `time.time() + 3000`.

If `QNAP_API_URL` is not configured, return a JSON error object instead of raising — this matches the pattern of `query_qnap_health` for graceful degradation.

**Acceptance criteria:**
- Function is decorated with `@tool` and appears in `query_qnap_health`'s module, importable as `from agent.tools.qnap_tools import query_qnap_directory_sizes`.
- A unit test with mocked HTTP responses validates: auth is called once, `get_tree` is called with the correct `path` and `sid`, and the returned JSON contains entries sorted by `size_bytes` descending.
- A second call within the session window does not re-authenticate (mock asserts `authLogin.cgi` called only once across two `query_qnap_directory_sizes` calls).
- If `qnap_api_url` is `None`, returns `{"error": "QNAP_API_URL not configured"}` as JSON.
- Three new env var fields are documented in `CONFIGURATION_GUIDE.md`.

---

### S2-06: Fix VLAN map and trust levels in system.py prompts

**File:** `/Users/tbailey/Dev/first-light/agent/prompts/system.py`

**Description:** The `NETWORK_KNOWLEDGE` constant is missing VLAN 3 (CCTV, 192.168.3.x) and VLAN 10 (Guest, 192.168.10.x). VLAN 2 is described as "IoT/Automation - Smart home devices, servers, IoT" without noting the critical distinction: VLAN 2 cannot reach VLAN 1, and `192.168.2.106` (NAS/docker host) has elevated trust. The prompt's incomplete topology means the synthesis agent may misinterpret cross-VLAN traffic alerts.

**Change:** Update `NETWORK_KNOWLEDGE` to:

```
## Network Topology
- **VLAN 1 (192.168.1.x)**: Main LAN — Trusted user devices; highest trust level
- **VLAN 2 (192.168.2.x)**: IoT — Smart home devices, servers; LOW trust, cannot reach VLAN 1
  - Exception: 192.168.2.106 (docker.mcducklabs.com / NAS) — HIGH trust, infrastructure host
- **VLAN 3 (192.168.3.x)**: CCTV — Security cameras; FULLY ISOLATED, no WAN, no cross-VLAN routing
- **VLAN 4 (192.168.4.x)**: DMZ — Ethereum validator; WAN-only, no internal network access
- **VLAN 10 (192.168.10.x)**: Guest WiFi — Untrusted, internet-only
```

Also add a security note: "Any traffic FROM VLAN 3 or TO VLAN 1 from VLAN 2 (except 192.168.2.106) should be treated as HIGH SEVERITY anomaly."

**Acceptance criteria:**
- The string `"192.168.3"` appears in `NETWORK_KNOWLEDGE`.
- The string `"192.168.10"` appears in `NETWORK_KNOWLEDGE`.
- The string `"192.168.2.106"` appears with `"trust"` context nearby.
- The string `"FULLY ISOLATED"` or `"fully isolated"` appears in reference to VLAN 3.

---

### Sprint 2 — Dependencies

- S2-02 (resolve.py rewrite) depends on S2-01 (topology.yaml complete) — the new resolve.py reads from topology at import time.
- S2-04 (Redis lock in scheduler) depends on S2-03 (Redis in compose) — need the service running to test.
- S2-05 (QNAP directory sizes) depends on S1-01 being done conceptually (establishes the pattern for reading credentials from `get_config()`).
- S2-06 is independent of all other Sprint 2 tickets.

---

## 4. Sprint 3 — Telegram Bot

**Goal:** Deliver the interactive Telegram bot: `bot/telegram_bot.py`, `run_interactive_query()` in `agent/graph.py`, Redis conversation history, and all wiring into `docker-compose.yml`. This is the major user-facing feature of the Epic.

**Duration target:** 1.5 weeks

---

### S3-01: Implement run_interactive_query() in agent/graph.py

**File:** `/Users/tbailey/Dev/first-light/agent/graph.py`

**Description:** After S1-08 strips out the dead `create_agent()` / `get_agent()` code, `graph.py` is mostly empty except for `create_system_prompt()` and the tool imports. This ticket adds the public function that the Telegram bot calls for free-text and `/ask` queries.

**Signature:**

```python
async def run_interactive_query(
    question: str,
    history: list[dict],
    thread_id: str,
) -> str:
    """
    Run an interactive query against all available tools.
    
    Args:
        question: The user's question or command
        history: Conversation history as list of {"role": str, "content": str} dicts
        thread_id: Stable ID for this conversation (used for LangGraph checkpointer)
    
    Returns:
        Markdown-formatted string suitable for Telegram
    
    Raises:
        Nothing — all exceptions caught and returned as error strings
    """
```

**Implementation:**

Use `agent.llm.run_react_loop` as the underlying engine (the same function used by domain agents). This is consistent with the rest of the system and gets Langfuse tracing for free.

Build the full tool set (same tools as the old `create_agent()` had, which can be referenced from the existing imports in `graph.py`):

```python
ALL_TOOLS = [
    query_adguard_top_clients, query_adguard_block_rates,
    query_adguard_high_risk_clients, query_adguard_blocked_domains,
    query_adguard_traffic_by_type,
    query_security_summary, query_wireless_health, query_infrastructure_events,
    search_logs_by_ip,
    query_threat_intel_summary, lookup_ip_threat_intel, query_threat_intel_coverage,
    query_qnap_health, query_qnap_directory_sizes,   # S2-05 adds this
    query_proxmox_health,
    query_validator_health,
]
```

History handling: prepend history messages to the `messages` list inside `run_react_loop`. Since `run_react_loop` builds `[system, user]` messages internally, extend it or build the initial message list externally. The cleanest approach is to add an optional `extra_messages: list[dict] = None` parameter to `run_react_loop` that is inserted between the system prompt and the user message.

Alternatively — and more self-contained — wrap `run_react_loop` directly:

```python
async def run_interactive_query(question, history, thread_id):
    loop = asyncio.get_event_loop()
    system = create_system_prompt()
    # Build history context prefix into user message
    if history:
        context = "\n".join(
            f"[{m['role'].upper()}]: {m['content']}" for m in history[-10:]
        )
        user = f"Previous conversation:\n{context}\n\nCurrent question: {question}"
    else:
        user = question
    
    try:
        result = await loop.run_in_executor(
            None,
            lambda: run_react_loop(system, user, ALL_TOOLS, "interactive", 
                                    agent_type="micro", session_id=thread_id)
        )
        return result
    except Exception as e:
        logger.error("Interactive query failed: %s", e, exc_info=True)
        return f"Sorry, I encountered an error: {e}"
```

Note: `run_react_loop` is synchronous (uses `litellm.completion` synchronously). Wrapping it in `run_in_executor` prevents it from blocking the asyncio event loop that the Telegram bot runs on.

**Acceptance criteria:**
- `await run_interactive_query("what is my network status", [], "test-thread-1")` returns a non-empty string (integration test with live tools).
- `await run_interactive_query("who is 192.168.1.1", [{"role": "user", "content": "check dns"}, {"role": "assistant", "content": "DNS looks good"}], "test-thread-2")` — the history is included in the LLM context (verify by checking the messages list passed to `run_react_loop` in a unit test with mocked `run_react_loop`).
- If all tools fail (mock all tools to raise), the function returns a string starting with `"Sorry"` rather than raising an exception.
- The function is `async` and can be called from an async context without event loop issues.

---

### S3-02: Implement bot/telegram_bot.py

**File:** `/Users/tbailey/Dev/first-light/bot/telegram_bot.py`

**Description:** The `bot/` directory is currently a stub (`__init__.py` only). This ticket implements the full Telegram bot using `python-telegram-bot>=21.0` (already in `requirements.txt`) with long polling.

**Architecture decisions:**
- Long polling (not webhook): the system runs behind NAT, so webhook is not viable without a relay.
- Security: `TELEGRAM_ALLOWED_CHAT_IDS` env var (comma-separated list of integer chat IDs). Any message from a non-allowed chat ID is silently dropped — no response, no error, not even a log at INFO level (to avoid information leakage about the bot's existence).
- Typing indicator: before any agent call, send `ChatAction.TYPING`. For long operations, re-send every 4 seconds using a background task.
- Message splitting: Telegram's limit is 4096 characters. Split on paragraph boundaries (`\n\n`). If a single paragraph exceeds 4096 characters, split on sentence boundaries (`. `) as fallback, then at 4096 as hard fallback.

**Commands to implement:**

`/start` and `/help`: Return a help message listing available commands.

`/status`: Call `query_uptime_kuma` and `query_qnap_health` and return a brief status. This is a lightweight command that should respond in under 10 seconds.

`/report`: Trigger `generate_daily_report()` from `agent/reports/daily_threat_assessment.py`. This is an expensive operation. The bot should respond immediately with "Generating report, this will take several minutes..." then send the report when complete. Use `asyncio.create_task` to run the report in the background and deliver it when done.

`/ask <question>`: Call `run_interactive_query(question, [], thread_id)` and return the result.

Free-text messages: Load conversation history from Redis key `tg:conv:{chat_id}`, call `run_interactive_query(message, history, thread_id)`, append the exchange to history (capped at last 20 messages), save back to Redis with 24-hour TTL, and return the result.

**Redis key usage (per spec):**
- `tg:conv:{chat_id}` — JSON list of `{"role": str, "content": str}` dicts, TTL 24h.
- `tg:session:{chat_id}` — active graph thread ID, TTL 1h.
- `report:lock:daily` — set in `scheduler.py` (S2-04), checked here before triggering `/report` to prevent double-runs.

**Typing indicator implementation:**

```python
async def typing_loop(context, chat_id: int, stop_event: asyncio.Event):
    """Send typing indicator every 4s until stop_event is set."""
    while not stop_event.is_set():
        await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)
        try:
            await asyncio.wait_for(asyncio.shield(stop_event.wait()), timeout=4.0)
        except asyncio.TimeoutError:
            pass
```

Call `asyncio.create_task(typing_loop(...))` before agent calls, set the stop event when the call returns.

**Message splitting implementation:**

```python
def split_message(text: str, limit: int = 4096) -> list[str]:
    """Split text into Telegram-safe chunks on paragraph boundaries."""
    if len(text) <= limit:
        return [text]
    chunks = []
    current = ""
    for paragraph in text.split("\n\n"):
        candidate = current + ("\n\n" if current else "") + paragraph
        if len(candidate) > limit:
            if current:
                chunks.append(current)
            current = paragraph
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks or [text[:limit]]
```

**Config additions to `config.py`:**

```python
telegram_allowed_chat_ids: Optional[str] = None  # comma-separated
redis_url: str = "redis://fl-redis:6379/0"
```

`telegram_allowed_chat_ids` is parsed into a `frozenset[int]` at bot startup.

**Acceptance criteria:**
- A message from a disallowed chat ID produces no response and no log at INFO or higher.
- `/help` responds within 2 seconds (no agent calls).
- `/ask what is my DNS block rate` responds with relevant content and completes within 60 seconds.
- Free-text message with prior conversation history includes that history in the agent call (verifiable by checking the Redis key before and after).
- After a free-text exchange, `redis-cli get tg:conv:{chat_id}` returns a JSON list with the new messages appended.
- A message longer than 4096 characters is split into multiple Telegram messages (verifiable by mocking `send_message` and checking call count).
- `/report` responds immediately with a "generating" message (within 3 seconds), then delivers the full report when ready.

---

### S3-03: Add bot service to docker-compose.yml

**File:** `/Users/tbailey/Dev/first-light/docker-compose.yml`

**Description:** Wire the Telegram bot into the compose stack as a separate service. It should share the `agent` service's Dockerfile (same Python environment) but run a different entrypoint.

**Change:**

```yaml
bot:
  build:
    context: .
    dockerfile: agent/Dockerfile
  container_name: fl-bot
  restart: unless-stopped
  command: python -m bot.telegram_bot
  env_file: .env
  environment:
    - TZ=America/Chicago
    - REDIS_URL=redis://fl-redis:6379/0
  networks:
    - signoz-net
  depends_on:
    - redis
    - clickhouse
  healthcheck:
    test: ["CMD", "python", "-c", "import bot.telegram_bot; print('ok')"]
    interval: 60s
    timeout: 10s
    retries: 3
```

Add `TELEGRAM_ALLOWED_CHAT_IDS` to the `.env` template and `CONFIGURATION_GUIDE.md`.

Ensure `bot/telegram_bot.py` has an `if __name__ == "__main__": main()` entry point, and a `main()` function that the `python -m bot.telegram_bot` invocation uses.

Also add `bot/__init__.py` (it already exists per `ls` output, so verify it is properly set up).

**Acceptance criteria:**
- `docker-compose build bot` exits 0.
- `docker-compose up -d bot` starts the container.
- `docker-compose logs bot` shows the bot polling Telegram within 10 seconds of startup.
- The bot service restarts automatically if it crashes (verify with `restart: unless-stopped` behavior).
- Sending `/help` to the Telegram bot from an allowed chat ID produces a response within 5 seconds.

---

### S3-04: Add CONFIGURATION_GUIDE.md updates

**File:** `/Users/tbailey/Dev/first-light/CONFIGURATION_GUIDE.md`

**Description:** Three sprints add new environment variables. Document them all.

**New variables to document:**

From S1-01: None (validator uses existing `VALIDATOR_HOST`, `CONSENSUS_METRICS_PORT`, `EXECUTION_METRICS_PORT`).

From S2-03/S2-04:
- `REDIS_URL` — Redis connection URL, default `redis://fl-redis:6379/0`

From S2-05:
- `QNAP_API_URL` — QNAP web UI URL (e.g., `http://nas.mcducklabs.com:8080`)
- `QNAP_API_USER` — QNAP admin username
- `QNAP_API_PASS` — QNAP admin password

From S3-02/S3-03:
- `TELEGRAM_ALLOWED_CHAT_IDS` — Comma-separated list of Telegram chat IDs permitted to use the bot (e.g., `123456789,987654321`). Required for bot security.

**Acceptance criteria:**
- `CONFIGURATION_GUIDE.md` has a section for each new variable with: description, example value, required vs optional, and which service uses it.

---

### Sprint 3 — Dependencies

- S3-01 (`run_interactive_query`) depends on S1-08 (graph.py cleanup) and S2-05 (`query_qnap_directory_sizes`) for the full tool set.
- S3-02 (`telegram_bot.py`) depends on S3-01 (needs `run_interactive_query`) and S2-03 (needs Redis).
- S3-03 (compose service) depends on S3-02 (needs the bot file to exist).
- S3-04 (docs) is independent but should be done last to capture all new variables.

---

## 5. Integration Test Plan

### Philosophy

Unit tests cover: pure functions with mockable I/O (SQL injection validation, message splitting, resolve.py lookup chain, `split_message`, `typing_loop`, Redis key format). Integration tests cover: the live stack — ClickHouse queries, LiteLLM routing, Langfuse tracing, QNAP API, Telegram bot end-to-end.

### Infrastructure Requirements for Integration Tests

- ClickHouse running and reachable at `clickhouse:8123` (the SigNoz stack)
- Redis running at `fl-redis:6379`
- LiteLLM proxy accessible at `LITELLM_BASE_URL`
- Langfuse accessible at `LANGFUSE_HOST`
- QNAP NAS accessible at `QNAP_API_URL` (optional — skip if not available)
- `.env` file with all required variables

### scripts/test_integration.py — Design

**Location:** `/Users/tbailey/Dev/first-light/scripts/test_integration.py`

The existing `scripts/test_connections.py` tests basic connectivity. The new integration test file is a pytest suite organized by concern:

```
scripts/test_integration.py
├── class TestStack1_Tools          — verify each tool returns valid data
├── class TestStack1_Graph          — verify the full daily report pipeline
├── class TestStack2_Resolve        — verify resolve.py against live network
├── class TestStack2_Redis          — verify Redis connectivity and key schema
├── class TestStack2_QNAP           — verify QNAP directory sizes tool
└── class TestStack3_Bot            — verify run_interactive_query
```

**TestStack1_Tools — Unit/integration for individual tools**

```python
class TestStack1_Tools:
    def test_query_validator_health_returns_json(self):
        """validator.py: NIMBUS_URL/NETHERMIND_URL read from config, not hardcoded."""
        result = query_validator_health.invoke({})
        data = json.loads(result)
        assert "consensus" in data
        assert "execution" in data
        # Verify the URL is NOT the old hardcoded value if VALIDATOR_HOST is overridden
    
    def test_search_logs_by_ip_rejects_injection(self):
        """logs.py: SQL injection attempt is rejected or neutralized."""
        result = search_logs_by_ip.invoke({"ip_address": "'; DROP TABLE logs; --", "hours": 1})
        # Either raises ValueError or returns an error JSON — not an empty success
        assert "error" in result.lower() or "invalid" in result.lower()
    
    def test_search_logs_by_ip_valid_ip(self):
        """logs.py: valid IP returns JSON with expected schema."""
        result = search_logs_by_ip.invoke({"ip_address": "192.168.1.1", "hours": 1})
        data = json.loads(result)
        assert "ip_address" in data
        assert "sources" in data
    
    def test_enrich_ip_column_timeout_bounded(self):
        """resolve.py: enrich_ip_column with 25 IPs completes within 30s."""
        import time
        # Build text with 25 non-resolving IPs
        text = " ".join(f"192.168.100.{i}" for i in range(1, 26))
        start = time.time()
        enrich_ip_column(text)
        elapsed = time.time() - start
        assert elapsed < 30, f"enrich_ip_column took {elapsed:.1f}s — timeout not working"
```

**TestStack1_Graph — End-to-end daily report**

```python
class TestStack1_Graph:
    @pytest.mark.timeout(300)  # 5 minutes max
    def test_daily_report_completes(self):
        """Full LangGraph pipeline produces a non-empty report."""
        from agent.graphs.daily_report_graph import generate_daily_report
        report = generate_daily_report(hours=24)
        assert len(report) > 500
        assert "##" in report  # Has markdown headers
    
    def test_daily_report_no_utcnow_warnings(self):
        """No DeprecationWarning from datetime.utcnow()."""
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            from agent.graphs.daily_report_graph import generate_daily_report
            # Import must not trigger warnings (module-level issues)
```

**TestStack2_Resolve — Live resolve.py**

```python
class TestStack2_Resolve:
    def test_topology_index_loaded(self):
        """resolve.py loads topology at import."""
        from agent.utils.resolve import _topology_index
        assert "192.168.2.106" in _topology_index
        assert "nas" in _topology_index["192.168.2.106"].lower()
    
    def test_prime_ntopng_cache(self):
        """prime_ntopng_cache populates the module cache."""
        from agent.utils import resolve as r
        r.prime_ntopng_cache([{"ip": "192.168.99.1", "name": "test-device"}])
        result = r.resolve_hostname("192.168.99.1")
        assert "test-device" in result
    
    def test_resolve_known_ip_no_network(self):
        """NAS IP resolves from topology without network call."""
        from agent.utils.resolve import resolve_hostname
        resolve_hostname.cache_clear()
        result = resolve_hostname("192.168.2.106")
        assert "nas" in result.lower() or "192.168.2.106" in result
```

**TestStack2_Redis — Redis connectivity and key schema**

```python
class TestStack2_Redis:
    @pytest.fixture
    def redis_client(self):
        import redis
        r = redis.Redis.from_url(os.environ["REDIS_URL"])
        yield r
        # cleanup
        r.delete("test:fl:integration")
    
    def test_redis_connection(self, redis_client):
        """Redis is reachable and responds to PING."""
        assert redis_client.ping()
    
    def test_conversation_key_schema(self, redis_client):
        """tg:conv:{chat_id} key stores and retrieves JSON conversation."""
        chat_id = 999999999  # Test chat ID
        key = f"tg:conv:{chat_id}"
        history = [{"role": "user", "content": "test"}, {"role": "assistant", "content": "ok"}]
        redis_client.setex(key, 86400, json.dumps(history))
        stored = json.loads(redis_client.get(key))
        assert stored == history
        redis_client.delete(key)
    
    def test_report_lock_schema(self, redis_client):
        """report:lock:daily key can be set and has correct TTL."""
        key = "report:lock:daily"
        acquired = redis_client.set(key, "1", nx=True, ex=600)
        assert acquired
        ttl = redis_client.ttl(key)
        assert 595 <= ttl <= 600
        redis_client.delete(key)
```

**TestStack2_QNAP — QNAP File Station API**

```python
@pytest.mark.skipif(not os.getenv("QNAP_API_URL"), reason="QNAP_API_URL not configured")
class TestStack2_QNAP:
    def test_qnap_health_live(self):
        """query_qnap_health returns valid JSON from live QNAP exporter."""
        from agent.tools.qnap_tools import query_qnap_health
        result = query_qnap_health.invoke({})
        data = json.loads(result)
        assert "system" in data
        assert "volumes" in data
    
    def test_qnap_directory_sizes_live(self):
        """query_qnap_directory_sizes returns top-N dirs from live QNAP."""
        from agent.tools.qnap_tools import query_qnap_directory_sizes
        result = query_qnap_directory_sizes.invoke({"path": "/share/CACHEDEV1_DATA", "top_n": 5})
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) <= 5
        assert all("size_gb" in d for d in data)
        # Verify sorted by size descending
        sizes = [d["size_bytes"] for d in data]
        assert sizes == sorted(sizes, reverse=True)
    
    def test_qnap_session_reuse(self):
        """Two consecutive calls use the same auth session (no double login)."""
        from agent.tools import qnap_tools
        qnap_tools._qnap_sid = None  # Reset
        with unittest.mock.patch("httpx.Client.post") as mock_post:
            mock_post.return_value.text = "<QDocRoot><authSid>test123</authSid></QDocRoot>"
            mock_post.return_value.status_code = 200
            # ... setup get mock too
            qnap_tools.query_qnap_directory_sizes.invoke({})
            qnap_tools.query_qnap_directory_sizes.invoke({})
            auth_calls = [c for c in mock_post.call_args_list if "authLogin" in str(c)]
            assert len(auth_calls) == 1
```

**TestStack3_Bot — run_interactive_query**

```python
class TestStack3_Bot:
    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_run_interactive_query_basic(self):
        """run_interactive_query returns a non-empty string for a simple question."""
        from agent.graph import run_interactive_query
        result = await run_interactive_query(
            "What is the current DNS block rate?",
            [],
            "test-thread-integration-1"
        )
        assert len(result) > 50
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_run_interactive_query_with_history(self):
        """run_interactive_query includes history in the prompt context."""
        from agent.graph import run_interactive_query
        history = [
            {"role": "user", "content": "How many VLANs do I have?"},
            {"role": "assistant", "content": "You have 5 VLANs."}
        ]
        # This call should be able to reference the prior exchange
        result = await run_interactive_query(
            "What was the answer to my previous question?",
            history,
            "test-thread-integration-2"
        )
        assert "5" in result or "VLAN" in result.upper()
    
    @pytest.mark.asyncio
    async def test_run_interactive_query_tool_failure_graceful(self):
        """run_interactive_query catches all exceptions and returns error string."""
        from agent.graph import run_interactive_query
        from unittest.mock import patch
        with patch("agent.llm.run_react_loop", side_effect=RuntimeError("test error")):
            result = await run_interactive_query("test", [], "test-thread-3")
        assert "error" in result.lower() or "sorry" in result.lower()
```

### Test Configuration

The integration test file should use a `pytest.ini` section (or `conftest.py`) to:

1. Mark all tests in `TestStack2_QNAP` with `@pytest.mark.skipif(not os.getenv("QNAP_API_URL"), ...)`.
2. Mark `TestStack1_Graph.test_daily_report_completes` with `@pytest.mark.slow` — this test takes 2–5 minutes and should not run in a quick sanity check.
3. Provide a `--quick` pytest option that deselects `@pytest.mark.slow` tests.

**Running the tests:**

```bash
# Quick sanity check (excludes slow tests, skips QNAP if not configured):
pytest scripts/test_integration.py -m "not slow" -v

# Full suite including daily report generation:
pytest scripts/test_integration.py -v

# Individual class:
pytest scripts/test_integration.py::TestStack2_Redis -v
```

---

## 6. Definition of Done — Full Epic

The Epic is complete when all of the following are true simultaneously:

**Codebase health:**
- Zero bare `except:` clauses in the agent package (`ruff check --select E722 agent/` exits 0).
- Zero `datetime.utcnow()` calls (`grep -r "utcnow" agent/` returns 0 matches).
- Zero hardcoded credential strings for validator, QNAP, or any other service.
- Zero SQL injection vectors in ClickHouse query functions.
- The six dead code files from S1-11 do not exist.
- `docker-compose config` exits 0 with no warnings about missing build contexts.

**Daily report pipeline:**
- `docker-compose up -d agent` starts and the daily report runs on schedule.
- The report is delivered to Telegram at the scheduled time.
- The Redis lock prevents duplicate runs on container restart within the same window.
- Langfuse shows a single trace per report run (not two due to the dual-client bug).

**Interactive bot:**
- The bot service is running in docker-compose.
- All four commands respond correctly: `/help`, `/status`, `/report`, `/ask`.
- Free-text conversation history persists across bot process restarts.
- Non-whitelisted chat IDs receive no response.
- A 5-minute conversation with the bot about live network data can be completed without errors.

**Infrastructure:**
- Redis is running in compose with 256 MB memory cap.
- `topology.yaml` has subnets for all 5 VLANs.
- `query_qnap_directory_sizes` is implemented and wired into the interactive tool set.
- `CONFIGURATION_GUIDE.md` documents all new environment variables.

**Testing:**
- `pytest scripts/test_integration.py -m "not slow" -v` passes in under 5 minutes on the live stack.
- `pytest scripts/test_integration.py -v` (full suite including slow) passes in under 10 minutes.
- All unit tests in `tests/` continue to pass.

---

## 7. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| QNAP File Station API auth method changed or undocumented | Medium | Medium | S2-05 includes graceful degradation; if API is unavailable, tool returns error JSON and the agent continues |
| Langfuse v4 `get_client()` doesn't expose `.get_prompt()` method (S1-06) | Low | Medium | Read Langfuse v4 SDK docs before implementing; if prompt API moved, `PromptManager` wraps whatever the new API provides |
| `python-telegram-bot` long polling conflicts with asyncio event loop | Low | High | `python-telegram-bot>=21.0` uses native asyncio; the `Application.run_polling()` method handles the event loop internally — use it as documented |
| Redis connection failure breaking the daily report | Low | Medium | S2-04 explicitly implements fallback: Redis error is logged but does not prevent report generation |
| `socket.gethostbyaddr` in a thread executor still blocks all 4 workers | Low | Medium | The 4-worker executor limits concurrency; the hard per-call timeout of 2 seconds means at most 8 seconds of DNS lookup wall time across all concurrent calls |

---

### Critical Files for Implementation

- `/Users/tbailey/Dev/first-light/agent/utils/resolve.py`
- `/Users/tbailey/Dev/first-light/agent/graph.py`
- `/Users/tbailey/Dev/first-light/bot/telegram_bot.py`
- `/Users/tbailey/Dev/first-light/docker-compose.yml`
- `/Users/tbailey/Dev/first-light/agent/tools/logs.py`