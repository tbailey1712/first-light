"""
Daily Report Graph — LangGraph implementation.

Six domain agents run via LangGraph Send API fan-out, results collected
via operator.add reducer, then passed to a synthesis node.

Flow:
  START
    └─ initialize  (fetch Langfuse prompts)
         └─ [Send x6]  run_domain  (parallel fan-out, sequential in sync invoke)
              └─ synthesize  (Opus — reads all summaries, writes final report)
                   └─ END

Public interface (unchanged from ThreadPoolExecutor version):
    generate_daily_report(hours=24) -> str
"""

import logging
import operator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
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
from agent.langfuse_integration import get_agent_prompt_with_fallback
from agent.model_config import create_llm_for_agent_type

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

# Hardcoded fallbacks (from agent/domains/daily_report.py constants)
# Empty string = domain node uses its own hardcoded constant
FALLBACK_PROMPTS = {k: "" for k in DOMAIN_AGENTS}


# ── State ──────────────────────────────────────────────────────────────────────

class DomainResult(TypedDict):
    domain: str
    summary: str


class DomainNodeInput(TypedDict):
    domain: str
    hours: int
    prompt_override: str   # empty = use domain function's hardcoded constant


class DailyReportState(TypedDict):
    hours: int
    domain_results: Annotated[list[DomainResult], operator.add]
    prompts: dict[str, str]
    final_report: Optional[str]


# ── Synthesis prompt (Langfuse fallback) ───────────────────────────────────────

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

Cross-VLAN rules:
- VLAN 3 (CCTV) generating ANY external or cross-VLAN traffic = CRITICAL
- VLAN 4 (DMZ) receiving inbound connections beyond Ethereum P2P ports (9000, 30303) = investigate
- VLAN 2 IoT devices with high DNS block rates may be normal telemetry — check device type before escalating

All IPs should be referred to by hostname where known.

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
    prompts = {}
    for domain, slug in LANGFUSE_PROMPT_NAMES.items():
        prompts[domain] = get_agent_prompt_with_fallback(slug, fallback="")

    fetched = [k for k, v in prompts.items() if v]
    if fetched:
        logger.info(f"Langfuse prompts fetched: {fetched}")
    else:
        logger.info("Langfuse prompts unavailable — using hardcoded fallbacks")

    return {"prompts": prompts}


def run_domain(state: DomainNodeInput) -> dict:
    """
    Single domain node, invoked 6 times in parallel via Send fan-out.
    Returns one DomainResult appended into domain_results via operator.add.
    """
    domain_name = state["domain"]
    hours = state["hours"]
    # TODO Phase 2: pass state["prompt_override"] into domain fn when supported

    fn = DOMAIN_AGENTS[domain_name]
    logger.info(f"Running {domain_name}...")
    try:
        summary = fn(hours)
    except Exception as e:
        logger.error(f"Domain node '{domain_name}' failed: {e}", exc_info=True)
        summary = f"**{domain_name}**: Agent failed — {e}"

    return {"domain_results": [{"domain": domain_name, "summary": summary}]}


def synthesize(state: DailyReportState) -> dict:
    """Synthesis node — reads all domain results, writes final markdown report."""
    domain_summaries = {r["domain"]: r["summary"] for r in state["domain_results"]}

    # Use Langfuse synthesis prompt if available, otherwise hardcoded fallback
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

    llm = create_llm_for_agent_type("synthesis")
    logger.info("Running synthesis node...")
    response = llm.invoke(messages)
    logger.info("Synthesis complete.")

    return {"final_report": response.content}


# ── Routing ────────────────────────────────────────────────────────────────────

def dispatch_domains(state: DailyReportState) -> list[Send]:
    """Fan-out: emit one Send per domain agent."""
    return [
        Send("run_domain", {
            "domain": domain_name,
            "hours": state["hours"],
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


# ── Public entrypoint (interface unchanged) ────────────────────────────────────

def generate_daily_report(hours: int = 24) -> str:
    """
    Run the full daily report pipeline via LangGraph.

    Interface preserved from the ThreadPoolExecutor implementation.
    Called by agent/reports/daily_threat_assessment.py via run_in_executor.

    Args:
        hours: Lookback window (default 24h)

    Returns:
        Final report markdown string
    """
    start = datetime.utcnow()
    logger.info("=== Daily Report Generation Start (LangGraph) ===")

    initial_state: DailyReportState = {
        "hours": hours,
        "domain_results": [],
        "prompts": {},
        "final_report": None,
    }

    result = graph.invoke(initial_state)

    elapsed = (datetime.utcnow() - start).total_seconds()
    logger.info(f"=== Daily Report Complete in {elapsed:.1f}s ===")

    return result.get("final_report") or ""


# ── CLI test entrypoint ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    from dotenv import load_dotenv
    load_dotenv()

    hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24

    SEPARATOR = "=" * 72

    print(f"\n{SEPARATOR}")
    print(f"FIRST LIGHT DAILY REPORT — LangGraph  ({hours}h window)")
    print(f"Started: {datetime.utcnow().isoformat()}Z")
    print(SEPARATOR)

    report = generate_daily_report(hours)
    print(report)

    print(f"\n{SEPARATOR}")
    print(f"Done: {datetime.utcnow().isoformat()}Z")
    print(SEPARATOR)
