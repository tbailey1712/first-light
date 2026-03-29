"""
Daily Report Graph — LangGraph implementation.

Six domain agents run via LangGraph Send API fan-out, results collected
via operator.add reducer, then passed to a synthesis node.

Flow:
  START
    └─ initialize  (fetch Langfuse prompts)
         └─ [Send x6]  run_domain  (fan-out)
              └─ synthesize  (writes final report)
                   └─ END

All LLM calls go through agent.llm — tracing handled there.

Public interface:
    generate_daily_report(hours=24) -> str
"""

import logging
import operator
from datetime import datetime, timezone
from typing import Annotated, Optional, TypedDict

from langgraph.graph import StateGraph, START, END
from langgraph.types import Send

from agent.domains.daily_report import (
    run_firewall_threat_agent,
    run_dns_agent,
    run_network_flow_agent,
    run_infrastructure_agent,
    run_wireless_agent,
    run_validator_agent,
)
from langfuse import observe
from agent.langfuse_integration import get_agent_prompt_with_fallback
from agent.llm import chat

logger = logging.getLogger(__name__)


# ── Domain agent registry ──────────────────────────────────────────────────────

DOMAIN_AGENTS = {
    "firewall_threat": run_firewall_threat_agent,
    "dns_security":    run_dns_agent,
    "network_flow":    run_network_flow_agent,
    "infrastructure":  run_infrastructure_agent,
    "wireless":        run_wireless_agent,
    "validator":       run_validator_agent,
}

LANGFUSE_PROMPT_NAMES = {
    "firewall_threat": "first-light-firewall-threat",
    "dns_security":    "first-light-dns",
    "network_flow":    "first-light-network-flow",
    "infrastructure":  "first-light-infrastructure",
    "wireless":        "first-light-wireless",
    "validator":       "first-light-validator",
    "synthesis":       "first-light-synthesis",
}


# ── State ──────────────────────────────────────────────────────────────────────

class DomainResult(TypedDict):
    domain: str
    summary: str


class DomainNodeInput(TypedDict):
    domain: str
    hours: int
    session_id: str
    prompt_override: str


class DailyReportState(TypedDict):
    hours: int
    session_id: str
    domain_results: Annotated[list[DomainResult], operator.add]
    prompts: dict[str, str]
    final_report: Optional[str]


# ── Synthesis prompt fallback ──────────────────────────────────────────────────

SYNTHESIS_SYSTEM = """You are First Light AI, the synthesis agent for a home/prosumer network observability platform.

You have received summary reports from 6 specialized domain agents that each independently analysed
the past 24 hours of network and infrastructure data. Your job is to:

1. Synthesize their findings into a single coherent daily security and health report
2. Identify cross-domain correlations (e.g., an IP that appears in both DNS blocks and firewall blocks)
3. Prioritize findings by severity — surface what actually matters
4. Produce a clean, scannable Markdown report for the operator

Network context:
- VLAN 1: Main LAN — trusted user devices, highest trust
- VLAN 2: IoT Devices — cannot reach VLAN 1, has WAN access
- VLAN 3: CCTV — fully isolated, no WAN, no cross-VLAN (any external traffic = CRITICAL)
- VLAN 4: DMZ — WAN only (Ethereum validator)
- VLAN 10: WiFi Guest
- VLAN 2 IoT devices with high DNS block rates may be normal telemetry — check device type before escalating

Severity levels:
- 🔴 CRITICAL: Active threat, service down, validator offline, cross-VLAN breach
- 🟡 WARNING: Anomaly, threshold approached, degraded state
- 🟢 INFO / ✅ OK: Routine, healthy, nominal

Report structure:
## Executive Summary
2-3 sentences. Overall posture. Action required or all clear.

## 🔴 Critical Issues  (omit section if none)
## 🟡 Warnings  (omit section if none)
## 🛡️ Threat Intelligence
## 🌐 Network & DNS
## 🖥️ Infrastructure
## 📡 Wireless
## ⛓️ Validator
## ✅ Action Items  (only if actions are ACTUALLY needed)

Rules:
- Be specific: IPs/hostnames, counts, scores, percentages
- Omit sections that have nothing to say
- Do not repeat the same finding in multiple sections
- Skip boilerplate like "The analysis showed..." or "Overall the network is..."
- Use emojis for scannability
"""

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

Write the final synthesized report now.
"""


# ── Nodes ──────────────────────────────────────────────────────────────────────

def initialize(state: DailyReportState) -> dict:
    """Fetch Langfuse prompts for all domains. Falls back gracefully."""
    hours = state["hours"]
    prompts = {}

    for domain, slug in LANGFUSE_PROMPT_NAMES.items():
        if domain == "synthesis":
            prompts[domain] = get_agent_prompt_with_fallback(slug, fallback="")
        else:
            prompts[domain] = get_agent_prompt_with_fallback(slug, fallback="", hours=hours)

    fetched = [k for k, v in prompts.items() if v]
    if fetched:
        logger.info(f"Langfuse prompts fetched: {fetched}")
    else:
        logger.info("Langfuse prompts unavailable — using hardcoded fallbacks")

    return {"prompts": prompts}


def run_domain(state: DomainNodeInput) -> dict:
    """
    Single domain node, invoked 6 times via Send fan-out.
    Returns one DomainResult appended into domain_results via operator.add.
    """
    domain_name = state["domain"]
    hours = state["hours"]
    session_id = state["session_id"]
    prompt_override = state.get("prompt_override") or ""

    fn = DOMAIN_AGENTS[domain_name]
    logger.info(
        "Running %s%s...", domain_name,
        " (Langfuse prompt)" if prompt_override else " (hardcoded prompt)"
    )
    try:
        summary = fn(hours, prompt_override=prompt_override, session_id=session_id)
    except Exception as e:
        logger.error(f"Domain node '{domain_name}' failed: {e}", exc_info=True)
        summary = f"**{domain_name}**: Agent failed — {e}"

    return {"domain_results": [{"domain": domain_name, "summary": summary}]}


def synthesize(state: DailyReportState) -> dict:
    """Synthesis node — reads all domain results, writes final markdown report."""
    domain_summaries = {r["domain"]: r["summary"] for r in state["domain_results"]}

    synthesis_system = state["prompts"].get("synthesis") or SYNTHESIS_SYSTEM

    date_str = datetime.now().strftime("%Y-%m-%d")
    user_message = SYNTHESIS_USER.format(
        date=date_str,
        hours=state["hours"],
        firewall_threat=domain_summaries.get("firewall_threat", "No data"),
        dns_security=domain_summaries.get("dns_security", "No data"),
        network_flow=domain_summaries.get("network_flow", "No data"),
        infrastructure=domain_summaries.get("infrastructure", "No data"),
        wireless=domain_summaries.get("wireless", "No data"),
        validator=domain_summaries.get("validator", "No data"),
    )

    messages = [
        {"role": "system", "content": synthesis_system},
        {"role": "user", "content": user_message},
    ]

    logger.info("Running synthesis node...")
    response = chat(messages, "synthesis", session_id=state["session_id"], agent_name="synthesis")
    logger.info("Synthesis complete.")

    return {"final_report": response.choices[0].message.content}


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

_builder = StateGraph(DailyReportState)
_builder.add_node("initialize", initialize)
_builder.add_node("run_domain", run_domain)
_builder.add_node("synthesize", synthesize)

_builder.add_edge(START, "initialize")
_builder.add_conditional_edges("initialize", dispatch_domains, ["run_domain"])
_builder.add_edge("run_domain", "synthesize")
_builder.add_edge("synthesize", END)

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

    # Tag this trace in Langfuse
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
        "final_report": None,
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
