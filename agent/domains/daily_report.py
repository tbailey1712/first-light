"""
Daily Report Domain Agents

Six specialized domain agents that each run their own ReAct analysis loop
using domain-relevant tools, then return a concise markdown summary.

Each agent:
  1. Receives a focused system prompt + relevant tools
  2. Runs a ReAct loop (up to 12 tool calls) to gather data
  3. Returns a plain-text / markdown summary of its domain

These summaries are collected and handed to the synthesis agent in
agent/graphs/daily_report_graph.py.
"""

import logging
from typing import Optional

from agent.llm import run_react_loop

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Domain Agent: Firewall & Threat Intelligence
# ─────────────────────────────────────────────

FIREWALL_THREAT_SYSTEM = """You are a firewall and threat intelligence analyst for a home/prosumer network.

Your job:
- Analyse the past {hours} hours of pfSense firewall blocks and ntopng security alerts
- Identify confirmed malicious IPs using the threat intelligence enrichment data
- Highlight IPs with high threat scores (>50), their country/ASN, and what they attempted
- Note cross-VLAN traffic from Camera VLAN (3) or Validator VLAN (4) — always CRITICAL

Threat score scale:
  0-25: Low risk    |  25-50: Moderate  |  50-75: High risk  |  75-100: Confirmed malicious

Tools to call:
1. query_threat_intel_summary(hours={hours}, min_score=0) — START HERE
2. query_security_summary(hours={hours}) — raw firewall blocks / ntopng context
3. lookup_ip_threat_intel(ip) — for any IP with score > 50 (max 5 IPs)

Return a focused markdown summary with:
- Count of firewall blocks, unique attacker IPs
- Confirmed malicious IPs (threat_score > 50) — IP, score, country, what they tried
- Notable ntopng alerts
- Any CRITICAL cross-VLAN events

Be specific: include IPs, counts, ports. Skip generic commentary.
"""

FIREWALL_THREAT_USER = "Analyse firewall blocks and threat intelligence for the past {hours} hours."


def run_firewall_threat_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the firewall + threat intelligence domain agent."""
    from agent.tools.logs import query_security_summary
    from agent.tools.threat_intel_tools import (
        query_threat_intel_summary,
        lookup_ip_threat_intel,
        query_threat_intel_coverage,
    )

    tools = [query_threat_intel_summary, query_security_summary, lookup_ip_threat_intel, query_threat_intel_coverage]
    system = prompt_override or FIREWALL_THREAT_SYSTEM.format(hours=hours)
    user = FIREWALL_THREAT_USER.format(hours=hours)

    logger.info("Running firewall_threat_agent...")
    try:
        return run_react_loop(system, user, tools, "firewall_threat", session_id=session_id)
    except Exception as e:
        logger.error(f"firewall_threat_agent failed: {e}", exc_info=True)
        return f"**Firewall/Threat Intel**: Agent failed — {e}"


# ─────────────────────────────────────────────
# Domain Agent: DNS Security
# ─────────────────────────────────────────────

DNS_SYSTEM = """You are a DNS security analyst for a home/prosumer network using AdGuard Home.

Your job:
- Review DNS query volume, block rates, and high-risk clients for the past {hours} hours
- Identify devices making unusually high numbers of blocked requests
- Surface blocked domains that are high-risk (malware, phishing, tracking)
- Flag any DGA-like query patterns or suspicious query types

Tools to call:
1. query_adguard_block_rates(hours={hours})
2. query_adguard_high_risk_clients(hours={hours})
3. query_adguard_blocked_domains(hours={hours})
4. query_adguard_top_clients(hours={hours})
5. query_adguard_traffic_by_type(hours={hours})

Return a focused markdown summary with:
- Total queries, block rate %
- Top blocked categories / domains
- Any clients with anomalous behaviour (high blocks, unusual query types)
- Items that warrant attention

Be specific: include client IPs, domain names, counts. Skip normal/expected activity.
"""

DNS_USER = "Analyse DNS security activity for the past {hours} hours."


def run_dns_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the DNS security domain agent."""
    from agent.tools.metrics import (
        query_adguard_top_clients,
        query_adguard_block_rates,
        query_adguard_high_risk_clients,
        query_adguard_blocked_domains,
        query_adguard_traffic_by_type,
    )

    tools = [
        query_adguard_block_rates,
        query_adguard_high_risk_clients,
        query_adguard_blocked_domains,
        query_adguard_top_clients,
        query_adguard_traffic_by_type,
    ]
    system = prompt_override or DNS_SYSTEM.format(hours=hours)
    user = DNS_USER.format(hours=hours)

    logger.info("Running dns_agent...")
    try:
        return run_react_loop(system, user, tools, "dns_security", session_id=session_id)
    except Exception as e:
        logger.error(f"dns_agent failed: {e}", exc_info=True)
        return f"**DNS Security**: Agent failed — {e}"


# ─────────────────────────────────────────────
# Domain Agent: Network Flow (ntopng)
# ─────────────────────────────────────────────

NETWORK_FLOW_SYSTEM = """You are a network flow analyst for a home/prosumer network using ntopng.

Your job:
- Review active network flows, top talkers, and protocol distribution
- Identify unusual flow patterns, unexpected protocols, or bandwidth anomalies
- Surface any security alerts from ntopng (IDS/IPS hits, anomaly detection)
- Note significant L7 protocol usage (unexpected applications)

Tools to call:
1. query_ntopng_alerts(max_alerts=20)
2. query_ntopng_interface_stats()
3. query_ntopng_active_hosts(max_hosts=20)
4. query_ntopng_l7_protocols()
5. query_ntopng_active_flows(max_flows=20) — only if alerts/hosts indicate something interesting

Return a focused markdown summary with:
- Interface traffic overview (bandwidth, flow count)
- ntopng security alerts (if any)
- Top talkers if anomalous
- Unusual L7 protocol usage

Skip normal traffic. Only surface what's unusual or noteworthy.
"""

NETWORK_FLOW_USER = "Analyse network flow data and ntopng alerts for the past {hours} hours."


def run_network_flow_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the network flow (ntopng) domain agent."""
    from agent.tools.ntopng import (
        query_ntopng_alerts,
        query_ntopng_interface_stats,
        query_ntopng_active_hosts,
        query_ntopng_l7_protocols,
        query_ntopng_active_flows,
        query_ntopng_interfaces,
    )

    tools = [
        query_ntopng_alerts,
        query_ntopng_interface_stats,
        query_ntopng_active_hosts,
        query_ntopng_l7_protocols,
        query_ntopng_active_flows,
        query_ntopng_interfaces,
    ]
    system = prompt_override or NETWORK_FLOW_SYSTEM
    user = NETWORK_FLOW_USER.format(hours=hours)

    logger.info("Running network_flow_agent...")
    try:
        return run_react_loop(system, user, tools, "network_flow", session_id=session_id)
    except Exception as e:
        logger.error(f"network_flow_agent failed: {e}", exc_info=True)
        return f"**Network Flow**: Agent failed — {e}"


# ─────────────────────────────────────────────
# Domain Agent: Infrastructure Health
# ─────────────────────────────────────────────

INFRASTRUCTURE_SYSTEM = """You are an infrastructure health analyst for a home server environment.

Your job:
- Review Docker container health, service errors, and system events for the past {hours} hours
- Check QNAP NAS: volumes, disks (SMART), temperatures, CPU/memory
- Check Proxmox VE: node health, VM/container status, storage utilization
- Flag anything degraded, stopped unexpectedly, or approaching capacity limits

Tools to call:
1. query_infrastructure_events(hours={hours}) — Docker / HA / Proxmox log events
2. query_qnap_health() — NAS volumes, disks, temperatures
3. query_proxmox_health() — Proxmox node, VMs, containers, storage

Return a focused markdown summary with:
- Overall infrastructure health (healthy / warnings / critical)
- Any container restarts, service errors, or Docker unhealthy states
- QNAP: volume status, any degraded disks, high temps
- Proxmox: node health, stopped VMs, storage usage
- Items requiring attention

Skip routine/healthy items. Focus on what needs attention.
"""

INFRASTRUCTURE_USER = "Analyse infrastructure health for the past {hours} hours."


def run_infrastructure_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the infrastructure health domain agent."""
    from agent.tools.logs import query_infrastructure_events
    from agent.tools.qnap_tools import query_qnap_health
    from agent.tools.proxmox_tools import query_proxmox_health
    from agent.tools.uptime_kuma import (
        query_uptime_kuma_status,
        query_uptime_kuma_uptime,
        query_uptime_kuma_incidents,
    )

    tools = [
        query_infrastructure_events,
        query_qnap_health,
        query_proxmox_health,
        query_uptime_kuma_status,
        query_uptime_kuma_uptime,
        query_uptime_kuma_incidents,
    ]
    system = prompt_override or INFRASTRUCTURE_SYSTEM.format(hours=hours)
    user = INFRASTRUCTURE_USER.format(hours=hours)

    logger.info("Running infrastructure_agent...")
    try:
        return run_react_loop(system, user, tools, "infrastructure", session_id=session_id)
    except Exception as e:
        logger.error(f"infrastructure_agent failed: {e}", exc_info=True)
        return f"**Infrastructure**: Agent failed — {e}"


# ─────────────────────────────────────────────
# Domain Agent: Wireless Health
# ─────────────────────────────────────────────

WIRELESS_SYSTEM = """You are a wireless network analyst for a home network using UniFi APs.

Your job:
- Review WiFi client events for the past {hours} hours
- Identify excessive deauth events, auth failures, or roaming problems
- Flag unknown or unexpected devices connecting to the network
- Surface any anomalous wireless client behaviour

Tools to call:
1. query_wireless_health(hours={hours})

Return a focused markdown summary with:
- Overall wireless health (healthy / issues detected)
- Deauth storms or mass disconnects
- Auth failures and suspicious devices
- Notable roaming or connectivity issues

Skip normal association/disassociation events. Only surface anomalies.
"""

WIRELESS_USER = "Analyse wireless network health for the past {hours} hours."


def run_wireless_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the wireless health domain agent."""
    from agent.tools.logs import query_wireless_health

    tools = [query_wireless_health]
    system = prompt_override or WIRELESS_SYSTEM.format(hours=hours)
    user = WIRELESS_USER.format(hours=hours)

    logger.info("Running wireless_agent...")
    try:
        return run_react_loop(system, user, tools, "wireless", session_id=session_id)
    except Exception as e:
        logger.error(f"wireless_agent failed: {e}", exc_info=True)
        return f"**Wireless**: Agent failed — {e}"


# ─────────────────────────────────────────────
# Domain Agent: Ethereum Validator
# ─────────────────────────────────────────────

VALIDATOR_SYSTEM = """You are an Ethereum validator analyst.

Your job:
- Check the health and performance of the Nimbus consensus client and Nethermind execution client
- Report sync status, peer counts, and any errors
- Flag missed attestations, missed proposals, or low peer counts
- Identify any service restarts or outages in the past {hours} hours

Tools to call:
1. query_validator_health(hours={hours})

Return a focused markdown summary with:
- Consensus client (Nimbus): sync status, peer count, errors
- Execution client (Nethermind): sync status, peer count, errors
- Any missed attestations or proposals
- Any validator outages or restarts

Be specific with numbers. Note if everything is nominal.
"""

VALIDATOR_USER = "Analyse Ethereum validator health for the past {hours} hours."


def run_validator_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the Ethereum validator domain agent."""
    from agent.tools.validator import query_validator_health

    tools = [query_validator_health]
    system = prompt_override or VALIDATOR_SYSTEM.format(hours=hours)
    user = VALIDATOR_USER.format(hours=hours)

    logger.info("Running validator_agent...")
    try:
        return run_react_loop(system, user, tools, "validator", session_id=session_id)
    except Exception as e:
        logger.error(f"validator_agent failed: {e}", exc_info=True)
        return f"**Validator**: Agent failed — {e}"
