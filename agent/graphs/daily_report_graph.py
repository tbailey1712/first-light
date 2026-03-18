"""
Daily Report Graph

Runs 6 domain agents in parallel via ThreadPoolExecutor, then passes
all domain summaries to a synthesis agent that writes the final report.

Flow:
  START
    └─ run_domain_agents_parallel (6 agents via ThreadPoolExecutor)
         └─ run_synthesis (Opus — reads all summaries, writes final report)
              └─ END
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict

from agent.domains.daily_report import (
    run_firewall_threat_agent,
    run_dns_agent,
    run_network_flow_agent,
    run_infrastructure_agent,
    run_wireless_agent,
    run_validator_agent,
)
from agent.model_config import create_llm_for_agent_type

logger = logging.getLogger(__name__)

# Domain agent registry: name → function
DOMAIN_AGENTS = {
    "firewall_threat": run_firewall_threat_agent,
    "dns_security": run_dns_agent,
    "network_flow": run_network_flow_agent,
    "infrastructure": run_infrastructure_agent,
    "wireless": run_wireless_agent,
    "validator": run_validator_agent,
}

SYNTHESIS_SYSTEM = """You are First Light AI, the synthesis agent for a home/prosumer network observability platform.

You have received summary reports from 6 specialized domain agents that each independently analysed
the past 24 hours of network and infrastructure data. Your job is to:

1. Synthesize their findings into a single coherent daily security and health report
2. Identify cross-domain correlations (e.g., an IP that appears in both DNS blocks and firewall blocks)
3. Prioritize findings by severity — surface what actually matters
4. Produce a clean, scannable Markdown report for the operator

Network context:
- VLAN 1: Management — highest trust
- VLAN 2: LAN — trusted user devices
- VLAN 3: Cameras — isolated, outbound internet should be minimal
- VLAN 4: Validator — Ethereum node, isolated
- VLAN 5: IoT — untrusted, no cross-VLAN access
- Any traffic FROM VLAN 3 or VLAN 4 to other VLANs = CRITICAL

Severity levels:
- 🔴 CRITICAL: Active threat, service down, validator offline, cross-VLAN breach
- 🟡 WARNING: Anomaly, threshold approached, degraded state
- 🟢 INFO / ✅ OK: Routine, healthy, nominal

Report structure:
## Executive Summary
2-3 sentences. Overall posture. Any-clear or action required.

## 🔴 Critical Issues  (omit section if none)
## 🟡 Warnings  (omit section if none)
## 🛡️ Threat Intelligence
## 🌐 Network & DNS
## 🖥️ Infrastructure
## 📡 Wireless
## ⛓️ Validator
## ✅ Action Items  (only if actions are ACTUALLY needed)

Rules:
- Be specific: IPs, counts, scores, percentages
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


def run_domain_agents_parallel(hours: int = 24) -> Dict[str, str]:
    """
    Execute all 6 domain agents in parallel using ThreadPoolExecutor.

    Args:
        hours: Lookback window for analysis

    Returns:
        Dict mapping domain name → summary text
    """
    results: Dict[str, str] = {}
    start = datetime.utcnow()

    logger.info(f"Starting parallel domain agent execution ({len(DOMAIN_AGENTS)} agents, {hours}h window)")

    def _run(name: str, fn) -> tuple[str, str]:
        try:
            summary = fn(hours)
            return name, summary
        except Exception as e:
            logger.error(f"Domain agent '{name}' raised unhandled exception: {e}", exc_info=True)
            return name, f"**{name}**: Agent raised exception — {e}"

    with ThreadPoolExecutor(max_workers=len(DOMAIN_AGENTS)) as executor:
        futures = {
            executor.submit(_run, name, fn): name
            for name, fn in DOMAIN_AGENTS.items()
        }
        for future in as_completed(futures):
            name, summary = future.result()
            results[name] = summary
            logger.info(f"  ✓ {name} complete ({len(summary)} chars)")

    elapsed = (datetime.utcnow() - start).total_seconds()
    logger.info(f"All domain agents complete in {elapsed:.1f}s")
    return results


def run_synthesis(domain_summaries: Dict[str, str], hours: int = 24) -> str:
    """
    Run the synthesis agent to produce the final report.

    Args:
        domain_summaries: Dict from run_domain_agents_parallel()
        hours: Lookback window (for context in prompt)

    Returns:
        Final report as markdown string
    """
    llm = create_llm_for_agent_type("synthesis")

    date_str = datetime.now().strftime("%Y-%m-%d")
    user_message = SYNTHESIS_USER.format(
        date=date_str,
        hours=hours,
        firewall_threat=domain_summaries.get("firewall_threat", "No data"),
        dns_security=domain_summaries.get("dns_security", "No data"),
        network_flow=domain_summaries.get("network_flow", "No data"),
        infrastructure=domain_summaries.get("infrastructure", "No data"),
        wireless=domain_summaries.get("wireless", "No data"),
        validator=domain_summaries.get("validator", "No data"),
    )

    messages = [
        {"role": "system", "content": SYNTHESIS_SYSTEM},
        {"role": "user", "content": user_message},
    ]

    logger.info("Running synthesis agent...")
    response = llm.invoke(messages)
    logger.info("Synthesis complete.")
    return response.content


def generate_daily_report(hours: int = 24) -> str:
    """
    Run the full daily report pipeline:
    1. All 6 domain agents in parallel
    2. Synthesis agent produces the final report

    Args:
        hours: Lookback window (default 24h)

    Returns:
        Final report markdown string
    """
    start = datetime.utcnow()
    logger.info("=== Daily Report Generation Start ===")

    # Step 1: Run domain agents in parallel
    domain_summaries = run_domain_agents_parallel(hours)

    # Step 2: Synthesis
    report_body = run_synthesis(domain_summaries, hours)

    elapsed = (datetime.utcnow() - start).total_seconds()
    logger.info(f"=== Daily Report Complete in {elapsed:.1f}s ===")

    return report_body


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
    print(f"FIRST LIGHT DAILY REPORT — TEST RUN  ({hours}h window)")
    print(f"Started: {datetime.utcnow().isoformat()}Z")
    print(SEPARATOR)

    # ── Step 1: Domain agents ──────────────────────────────────────────────
    print("\n>>> Running 6 domain agents in parallel ...\n")
    domain_summaries = run_domain_agents_parallel(hours)

    for domain, summary in domain_summaries.items():
        print(f"\n{SEPARATOR}")
        print(f"DOMAIN: {domain.upper()}")
        print(SEPARATOR)
        print(summary)

    # ── Step 2: Synthesis ──────────────────────────────────────────────────
    print(f"\n{SEPARATOR}")
    print("SYNTHESIS AGENT — FINAL REPORT")
    print(SEPARATOR + "\n")
    final_report = run_synthesis(domain_summaries, hours)
    print(final_report)

    print(f"\n{SEPARATOR}")
    print(f"Done: {datetime.utcnow().isoformat()}Z")
    print(SEPARATOR)
