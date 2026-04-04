"""
Daily Report Graph — LangGraph implementation.

Six domain agents run via LangGraph Send API fan-out, results collected
via operator.add reducer, then passed through a correlation pass before
a final synthesis node.

Flow:
  START
    └─ initialize  (fetch Langfuse prompts, load Redis baseline)
         └─ [Send x6]  run_domain  (fan-out)
              └─ correlate  (cross-domain IP/device lookups)
                   └─ synthesize  (writes final report, saves baseline)
                        └─ END

All LLM calls go through agent.llm — tracing handled there.

Public interface:
    generate_daily_report(hours=24) -> str
"""

import json
import logging
import operator
import re
from datetime import datetime, timezone
from typing import Annotated, Any, Optional, TypedDict

from langgraph.graph import StateGraph, START, END
from langgraph.types import Send

from agent.domains.daily_report import (
    run_firewall_threat_agent,
    run_dns_agent,
    run_network_flow_agent,
    run_infrastructure_agent,
    run_wireless_agent,
    run_validator_agent,
    run_cloudflare_agent,
)
from langfuse import observe
from agent.langfuse_integration import get_prompt_manager
from agent.llm import chat, run_react_loop

logger = logging.getLogger(__name__)

# ── Domain agent registry ──────────────────────────────────────────────────────

DOMAIN_AGENTS = {
    "firewall_threat": run_firewall_threat_agent,
    "dns_security":    run_dns_agent,
    "network_flow":    run_network_flow_agent,
    "infrastructure":  run_infrastructure_agent,
    "wireless":        run_wireless_agent,
    "validator":       run_validator_agent,
    "cloudflare":      run_cloudflare_agent,
}

LANGFUSE_PROMPT_NAMES = {
    "firewall_threat": "first-light-firewall-threat",
    "dns_security":    "first-light-dns",
    "network_flow":    "first-light-network-flow",
    "infrastructure":  "first-light-infrastructure",
    "wireless":        "first-light-wireless",
    "validator":       "first-light-validator",
    "cloudflare":      "first-light-cloudflare",
    "synthesis":       "first-light-synthesis",
    "correlation":     "first-light-correlation",
    "investigation":   "first-light-investigation",
}

# Redis key prefix for baseline storage
_REDIS_PREFIX = "fl:baseline:"

# IP address regex — matches private and public IPs in summary text
_IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

# IPs to never correlate — infrastructure, broadcast, etc.
_SKIP_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "192.168.1.1",   # pfSense LAN
    "192.168.2.1",   # pfSense IoT gateway
    "192.168.1.5",   # ntopng
    "192.168.2.106", # NAS / docker host
    "192.168.2.9",   # NAS QNAP
    "192.168.2.7",   # Frigate
    "192.168.2.8",   # PBS
}


# ── State ──────────────────────────────────────────────────────────────────────

class DomainResult(TypedDict):
    domain: str
    summary: str
    flagged_ips: list[str]      # IPs extracted from summary for correlation pass


class DomainNodeInput(TypedDict):
    domain: str
    hours: int
    session_id: str
    prompt_override: str


class SuspiciousItem(TypedDict):
    type: str           # "ip", "mac", "event"
    value: str          # the IP / MAC / event description
    reason: str         # why it's suspicious
    source_domain: str  # which domain flagged it


class DailyReportState(TypedDict):
    hours: int
    session_id: str
    domain_results: Annotated[list[DomainResult], operator.add]
    prompts: dict[str, str]
    baseline: dict[str, Any]        # yesterday's metrics from Redis
    correlation_findings: str       # output of correlation pass
    final_report: Optional[str]
    suspicious_items: list[SuspiciousItem]   # populated by synthesize Phase A
    investigation_findings: Optional[str]    # populated by investigate node


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_ips(text: str) -> list[str]:
    """Extract unique IP addresses from a text summary, excluding infrastructure IPs."""
    found = set(_IP_RE.findall(text))
    return sorted(found - _SKIP_IPS)


def _get_redis() -> Any:
    """Get a Redis client using the configured URL."""
    import redis as _redis
    from agent.config import get_config
    cfg = get_config()
    return _redis.from_url(cfg.redis_url, decode_responses=True)


def _load_baseline() -> dict[str, Any]:
    """Load yesterday's baseline metrics from Redis. Returns empty dict if unavailable."""
    try:
        r = _get_redis()
        keys = [
            "dns_queries", "dns_block_rate_pct",
            "firewall_blocks", "validator_balance_eth",
            "qnap_vol1_used_pct", "active_dhcp_count",
        ]
        baseline = {}
        for k in keys:
            val = r.get(f"{_REDIS_PREFIX}{k}")
            if val is not None:
                try:
                    baseline[k] = float(val)
                except ValueError:
                    baseline[k] = val
        return baseline
    except Exception as e:
        logger.warning(f"Redis baseline load failed: {e}")
        return {}


def _save_baseline(metrics: dict[str, Any]) -> None:
    """Save baseline metrics to Redis for next run's comparison."""
    try:
        r = _get_redis()
        for k, v in metrics.items():
            if v is not None:
                r.set(f"{_REDIS_PREFIX}{k}", str(v), ex=172800)  # 48h TTL
        logger.info(f"Baseline saved to Redis: {list(metrics.keys())}")
    except Exception as e:
        logger.warning(f"Redis baseline save failed: {e}")


def _format_baseline_context(baseline: dict[str, Any]) -> str:
    """Format baseline as a compact context block for the synthesis prompt."""
    if not baseline:
        return ""
    lines = ["Yesterday's baseline (for comparison):"]
    if "dns_queries" in baseline:
        lines.append(f"  DNS queries: {int(baseline['dns_queries']):,}")
    if "dns_block_rate_pct" in baseline:
        lines.append(f"  DNS block rate: {baseline['dns_block_rate_pct']:.1f}%")
    if "firewall_blocks" in baseline:
        lines.append(f"  Firewall blocks: {int(baseline['firewall_blocks']):,}")
    if "validator_balance_eth" in baseline:
        lines.append(f"  Validator balance: {baseline['validator_balance_eth']:.6f} ETH")
    if "qnap_vol1_used_pct" in baseline:
        lines.append(f"  QNAP Vol1 used: {baseline['qnap_vol1_used_pct']:.1f}%")
    if "active_dhcp_count" in baseline:
        lines.append(f"  Active DHCP devices: {int(baseline['active_dhcp_count'])}")
    return "\n".join(lines)


# ── Nodes ──────────────────────────────────────────────────────────────────────

def initialize(state: DailyReportState) -> dict:
    """Fetch Langfuse prompts for all domains and load Redis baseline. Raises if any prompt missing."""
    hours = state["hours"]
    manager = get_prompt_manager()
    prompts = {}

    for domain, slug in LANGFUSE_PROMPT_NAMES.items():
        if domain in ("synthesis", "correlation", "investigation"):
            prompts[domain] = manager.get_prompt(slug)
        else:
            prompts[domain] = manager.get_prompt(slug, hours=hours)

    logger.info(f"Langfuse prompts fetched: {list(prompts.keys())}")

    baseline = _load_baseline()
    if baseline:
        logger.info(f"Redis baseline loaded: {list(baseline.keys())}")
    else:
        logger.info("No Redis baseline available — first run or cache expired")

    return {"prompts": prompts, "baseline": baseline}


def run_domain(state: DomainNodeInput) -> dict:
    """Single domain node, invoked 6 times via Send fan-out."""
    domain_name = state["domain"]
    hours = state["hours"]
    session_id = state["session_id"]
    prompt_override = state.get("prompt_override") or ""

    fn = DOMAIN_AGENTS[domain_name]
    logger.info("Running %s (Langfuse prompt)...", domain_name)
    try:
        summary = fn(hours, prompt_override=prompt_override, session_id=session_id)
    except Exception as e:
        logger.error(f"Domain node '{domain_name}' failed: {e}", exc_info=True)
        summary = f"**{domain_name}**: Agent failed — {e}"

    flagged_ips = _extract_ips(summary)
    if flagged_ips:
        logger.info(f"{domain_name}: extracted {len(flagged_ips)} IPs for correlation")

    return {"domain_results": [{"domain": domain_name, "summary": summary, "flagged_ips": flagged_ips}]}


@observe(as_type="span", capture_input=False, capture_output=False)
def correlate(state: DailyReportState) -> dict:
    """
    Cross-domain correlation pass.

    Collects all IPs flagged across the 6 domain summaries, then runs a
    targeted ReAct agent to look them up cross-source. Produces a
    correlation_findings string injected between domain summaries and synthesis.
    """
    from langfuse import get_client as get_langfuse_client
    from opentelemetry import trace as otel_trace
    from langfuse import LangfuseOtelSpanAttributes
    from agent.tools.logs import search_logs_by_ip
    from agent.tools.threat_intel_tools import lookup_ip_threat_intel

    lf = get_langfuse_client()
    span = otel_trace.get_current_span()
    span.set_attribute(LangfuseOtelSpanAttributes.TRACE_SESSION_ID, state["session_id"])

    # Collect unique IPs across all domains, deduplicated
    domain_ip_map: dict[str, list[str]] = {}
    for result in state["domain_results"]:
        ips = result.get("flagged_ips", [])
        if ips:
            domain_ip_map[result["domain"]] = ips

    all_ips = sorted({ip for ips in domain_ip_map.values() for ip in ips})

    if not all_ips:
        logger.info("Correlation pass: no IPs to correlate")
        lf.update_current_span(output="No cross-domain entities flagged.")
        return {"correlation_findings": ""}

    logger.info(f"Correlation pass: {len(all_ips)} unique IPs from {list(domain_ip_map.keys())}")

    # Build ip-to-domain map for context
    ip_domain_context = {}
    for domain, ips in domain_ip_map.items():
        for ip in ips:
            ip_domain_context.setdefault(ip, []).append(domain)

    # IPs seen in multiple domains are highest priority
    multi_domain_ips = [ip for ip, domains in ip_domain_context.items() if len(domains) > 1]
    # Internal IPs flagged by DNS or infrastructure (potential compromised hosts)
    internal_flagged = [ip for ip in all_ips if ip.startswith("192.168.")]

    priority_ips = sorted(set(multi_domain_ips + internal_flagged))[:10]

    if not priority_ips:
        priority_ips = all_ips[:5]

    tools = [search_logs_by_ip, lookup_ip_threat_intel]

    correlation_prompt = state["prompts"].get("correlation", "")
    if not correlation_prompt:
        raise ValueError("Correlation agent requires Langfuse prompt 'first-light-correlation' with label=production")

    ip_context_lines = "\n".join(
        f"  {ip}: seen in [{', '.join(ip_domain_context.get(ip, []))}]"
        for ip in priority_ips
    )

    user_msg = (
        f"Cross-domain correlation pass for daily report. "
        f"The following IPs were flagged across domain agents:\n\n"
        f"{ip_context_lines}\n\n"
        f"Run targeted lookups on any IPs that appear in multiple domains or "
        f"that are internal addresses flagged as suspicious. "
        f"Report only genuinely correlated findings — skip IPs that come back clean."
    )

    try:
        findings = run_react_loop(
            correlation_prompt,
            user_msg,
            tools,
            "correlate",
            session_id=state["session_id"],
        )
    except Exception as e:
        logger.error(f"Correlation pass failed: {e}", exc_info=True)
        findings = f"Correlation pass failed: {e}"

    lf.update_current_span(output=findings[:500])
    return {"correlation_findings": findings}


def synthesize(state: DailyReportState) -> dict:
    """Synthesis node — reads domain results + correlation findings, writes final report.

    Phase A: structured suspicious-item extraction (best-effort, never blocks report).
    Phase B: full narrative synthesis.
    """
    domain_summaries = {r["domain"]: r["summary"] for r in state["domain_results"]}

    # ── Phase A: extract suspicious items for investigation ────────────────────
    suspicious_items: list[SuspiciousItem] = []
    try:
        all_summaries = "\n\n---\n\n".join(
            f"## {k.upper()}\n{v}" for k, v in domain_summaries.items()
        )
        if state.get("correlation_findings"):
            all_summaries += f"\n\n---\n\n## CORRELATION\n{state['correlation_findings']}"

        extraction_prompt = (
            "You are a security triage assistant. Review the domain summaries below and "
            "identify items that warrant deeper automated investigation. Return ONLY a JSON "
            "array (no markdown, no explanation) of objects with keys: "
            "type (ip/mac/event), value, reason, source_domain. "
            "Include only genuine anomalies: external IPs with threat scores > 60, "
            "internal IPs making unexpected cross-VLAN or external connections, "
            "devices with unusual behaviour, events explicitly flagged as suspicious. "
            "Return [] if nothing warrants investigation. Maximum 10 items.\n\n"
            f"{all_summaries}"
        )
        extract_response = chat(
            [{"role": "user", "content": extraction_prompt}],
            "synthesis",
            session_id=state["session_id"],
            agent_name="synthesize/extract",
        )
        raw = (extract_response.choices[0].message.content or "").strip()
        # Strip markdown fences if present
        raw = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw, flags=re.MULTILINE).strip()
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            suspicious_items = parsed[:10]
            if suspicious_items:
                logger.info("Synthesis Phase A: %d suspicious items flagged for investigation", len(suspicious_items))
    except Exception as e:
        logger.warning("Synthesis Phase A (suspicious item extraction) failed: %s — continuing", e)

    # ── Phase B: narrative synthesis ───────────────────────────────────────────
    synthesis_system = state["prompts"]["synthesis"]

    baseline_context = _format_baseline_context(state.get("baseline", {}))
    if baseline_context:
        synthesis_system = synthesis_system + f"\n\n{baseline_context}"

    if suspicious_items:
        synthesis_system += f"\n\nNote: {len(suspicious_items)} item(s) flagged for automated deep investigation — see Investigation Findings section that will follow this report."

    date_str = datetime.now().strftime("%Y-%m-%d")

    correlation_section = ""
    if state.get("correlation_findings"):
        correlation_section = f"""
---

## CROSS-DOMAIN CORRELATION FINDINGS
{state["correlation_findings"]}
"""

    user_message = SYNTHESIS_USER.format(
        date=date_str,
        hours=state["hours"],
        firewall_threat=domain_summaries.get("firewall_threat", "No data"),
        dns_security=domain_summaries.get("dns_security", "No data"),
        network_flow=domain_summaries.get("network_flow", "No data"),
        infrastructure=domain_summaries.get("infrastructure", "No data"),
        wireless=domain_summaries.get("wireless", "No data"),
        validator=domain_summaries.get("validator", "No data"),
        cloudflare=domain_summaries.get("cloudflare", "No data"),
        correlation_section=correlation_section,
    )

    messages = [
        {"role": "system", "content": synthesis_system},
        {"role": "user", "content": user_message},
    ]

    logger.info("Running synthesis node...")
    response = chat(messages, "synthesis", session_id=state["session_id"], agent_name="synthesis")
    final_report = response.choices[0].message.content or ""
    logger.info("Synthesis complete.")

    new_baseline = _extract_baseline_metrics(domain_summaries)
    if new_baseline:
        _save_baseline(new_baseline)

    return {"final_report": final_report, "suspicious_items": suspicious_items}


@observe(as_type="span", capture_input=False, capture_output=False)
def investigate(state: DailyReportState) -> dict:
    """Deep-dive ReAct agent for suspicious items flagged during synthesis."""
    from agent.tools.logs import search_logs_by_ip, query_outbound_blocks
    from agent.tools.threat_intel_tools import lookup_ip_threat_intel
    from agent.tools.ntopng import query_ntopng_flows_by_host, query_ntopng_active_hosts
    from agent.tools.investigation import query_clickhouse_raw

    from langfuse import get_client as get_langfuse_client
    from opentelemetry import trace as otel_trace
    from langfuse import LangfuseOtelSpanAttributes

    lf = get_langfuse_client()
    span = otel_trace.get_current_span()
    span.set_attribute(LangfuseOtelSpanAttributes.TRACE_SESSION_ID, state["session_id"])

    items = state.get("suspicious_items", [])
    if not items:
        return {"investigation_findings": None}

    tools = [
        search_logs_by_ip,
        lookup_ip_threat_intel,
        query_ntopng_flows_by_host,
        query_ntopng_active_hosts,
        query_outbound_blocks,
        query_clickhouse_raw,
    ]

    item_lines = "\n".join(
        f"  [{i+1}] type={item['type']} value={item['value']} "
        f"source={item['source_domain']} reason={item['reason']}"
        for i, item in enumerate(items)
    )
    user_msg = (
        f"Investigate the following {len(items)} suspicious item(s) flagged during today's report:\n\n"
        f"{item_lines}\n\n"
        "For each item: gather evidence, assess severity (low/medium/high/critical), "
        "identify the affected host, and recommend a specific action. "
        "Use all available tools. Cross-reference across sources. "
        "Produce a concise incident report grouped by item."
    )

    investigation_prompt = state["prompts"].get("investigation", "")
    if not investigation_prompt:
        investigation_prompt = (
            "You are a network security incident investigator for First Light. "
            "Investigate suspicious items using the available tools. "
            "Produce structured findings: severity, evidence, affected hosts, recommended actions."
        )

    logger.info("Running investigation node for %d item(s)...", len(items))
    try:
        findings = run_react_loop(
            investigation_prompt,
            user_msg,
            tools,
            "investigate",
            agent_type="supervisor",
            session_id=state["session_id"],
            max_iterations=20,
        )
    except Exception as e:
        logger.error("Investigation node failed: %s", e, exc_info=True)
        findings = f"Investigation failed: {e}"

    lf.update_current_span(output=findings[:500])
    return {"investigation_findings": findings}


def append_investigation(state: DailyReportState) -> dict:
    """Append investigation findings to the final report."""
    report = state.get("final_report") or ""
    findings = state.get("investigation_findings") or ""
    if findings:
        report += f"\n\n---\n\n## INCIDENT INVESTIGATION\n\n{findings}"
    return {"final_report": report}


def _extract_baseline_metrics(domain_summaries: dict[str, str]) -> dict[str, Any]:
    """
    Best-effort extraction of key metrics from domain summaries for Redis baseline storage.
    Uses simple regex patterns against the markdown text.
    """
    metrics: dict[str, Any] = {}

    dns = domain_summaries.get("dns_security", "")
    # Match "65,432 queries" or "65432 queries"
    m = re.search(r'([\d,]+)\s+(?:total\s+)?queries', dns)
    if m:
        try:
            metrics["dns_queries"] = float(m.group(1).replace(",", ""))
        except ValueError:
            pass
    # Match "8.2% block rate" or "block rate: 8.2%"
    m = re.search(r'(\d+\.?\d*)\s*%\s*block', dns, re.IGNORECASE)
    if m:
        try:
            metrics["dns_block_rate_pct"] = float(m.group(1))
        except ValueError:
            pass

    fw = domain_summaries.get("firewall_threat", "")
    m = re.search(r'([\d,]+)\s+(?:total\s+)?(?:firewall\s+)?blocks?', fw)
    if m:
        try:
            metrics["firewall_blocks"] = float(m.group(1).replace(",", ""))
        except ValueError:
            pass

    val = domain_summaries.get("validator", "")
    m = re.search(r'(\d+\.\d+)\s*ETH', val)
    if m:
        try:
            metrics["validator_balance_eth"] = float(m.group(1))
        except ValueError:
            pass

    infra = domain_summaries.get("infrastructure", "")
    # Anchor to a QNAP-specific context line before extracting percentage
    qnap_match = re.search(
        r'(?:QNAP|NAS|QVR)[^\n]*\n(?:[^\n]*\n){0,3}[^\n]*?(\d+\.?\d*)\s*%\s*(?:used|full|capacity)',
        infra, re.IGNORECASE
    )
    if qnap_match:
        try:
            metrics["qnap_vol1_used_pct"] = float(qnap_match.group(1))
        except ValueError:
            pass

    return metrics


# ── Synthesis user template ────────────────────────────────────────────────────

SYNTHESIS_USER = """Synthesize the following domain agent reports into the daily First Light report.

Analysis period: {date}, past {hours} hours

---

## FIREWALL & THREAT INTELLIGENCE
{firewall_threat}

---

## DNS SECURITY
{dns_security}

---

## NETWORK FLOW (ntopng)
{network_flow}

---

## INFRASTRUCTURE HEALTH
{infrastructure}

---

## WIRELESS
{wireless}

---

## ETHEREUM VALIDATOR
{validator}

---

## CLOUDFLARE EDGE SECURITY
{cloudflare}
{correlation_section}
---

Write the final synthesized report now.
"""


# ── Routing ────────────────────────────────────────────────────────────────────

def dispatch_domains(state: DailyReportState) -> list[Send]:
    """Fan-out: emit one Send per domain agent."""
    return [
        Send("run_domain", {
            "domain": domain_name,
            "hours": state["hours"],
            "session_id": state["session_id"],
            "prompt_override": state["prompts"].get(domain_name, ""),
        })
        for domain_name in DOMAIN_AGENTS
    ]


# ── Graph ──────────────────────────────────────────────────────────────────────

def should_investigate(state: DailyReportState) -> str:
    """Route to investigate if synthesis flagged suspicious items, else END."""
    return "investigate" if state.get("suspicious_items") else "end"


_builder = StateGraph(DailyReportState)
_builder.add_node("initialize", initialize)
_builder.add_node("run_domain", run_domain)
_builder.add_node("correlate", correlate)
_builder.add_node("synthesize", synthesize)
_builder.add_node("investigate", investigate)
_builder.add_node("append_investigation", append_investigation)

_builder.add_edge(START, "initialize")
_builder.add_conditional_edges("initialize", dispatch_domains, ["run_domain"])
_builder.add_edge("run_domain", "correlate")
_builder.add_edge("correlate", "synthesize")
_builder.add_conditional_edges("synthesize", should_investigate, {"investigate": "investigate", "end": END})
_builder.add_edge("investigate", "append_investigation")
_builder.add_edge("append_investigation", END)

graph = _builder.compile()


# ── Public entrypoint ──────────────────────────────────────────────────────────

@observe(as_type="span", capture_input=False, capture_output=False)
def generate_daily_report(hours: int = 24) -> str:
    """
    Run the full daily report pipeline via LangGraph.

    Args:
        hours: Lookback window (default 24h)

    Returns:
        Final report markdown string
    """
    import uuid
    from langfuse import get_client as get_langfuse_client, LangfuseOtelSpanAttributes
    from opentelemetry import trace as otel_trace

    start = datetime.now(timezone.utc)
    session_id = f"daily-report-{start.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    logger.info("=== Daily Report Generation Start (LangGraph) session=%s ===", session_id)

    lf = get_langfuse_client()
    span = otel_trace.get_current_span()
    span.set_attribute(LangfuseOtelSpanAttributes.TRACE_NAME, session_id)
    span.set_attribute(LangfuseOtelSpanAttributes.TRACE_SESSION_ID, session_id)
    span.set_attribute(LangfuseOtelSpanAttributes.TRACE_TAGS, ["daily-report"])
    lf.update_current_span(name="daily-report", input={"hours": hours})

    initial_state: DailyReportState = {
        "hours": hours,
        "session_id": session_id,
        "domain_results": [],
        "prompts": {},
        "baseline": {},
        "correlation_findings": "",
        "final_report": None,
        "suspicious_items": [],
        "investigation_findings": None,
    }

    result = graph.invoke(initial_state)
    final_report = result.get("final_report") or ""

    lf.update_current_span(output=final_report[:500])
    lf.flush()

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    logger.info("=== Daily Report Complete in %.1fs session=%s ===", elapsed, session_id)

    return final_report


# ── CLI test entrypoint ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    from dotenv import load_dotenv
    load_dotenv(override=True)

    hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24

    SEPARATOR = "=" * 72

    print(f"\n{SEPARATOR}")
    print(f"FIRST LIGHT DAILY REPORT — LangGraph  ({hours}h window)")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print(SEPARATOR)

    report = generate_daily_report(hours)
    print(report)

    print(f"\n{SEPARATOR}")
    print(f"Done: {datetime.now(timezone.utc).isoformat()}")
    print(SEPARATOR)
