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

FIREWALL_THREAT_USER = "Analyse firewall blocks and threat intelligence for the past {hours} hours."


def run_firewall_threat_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the firewall + threat intelligence domain agent."""
    from agent.tools.logs import query_security_summary, query_auth_events, query_outbound_blocks
    from agent.tools.threat_intel_tools import (
        query_threat_intel_summary,
        lookup_ip_threat_intel,
        query_threat_intel_coverage,
    )

    from agent.tools.crowdsec import query_crowdsec_alerts, query_crowdsec_decisions
    tools = [
        query_threat_intel_summary, query_security_summary,
        query_auth_events, query_outbound_blocks,
        lookup_ip_threat_intel, query_threat_intel_coverage,
        query_crowdsec_alerts, query_crowdsec_decisions,
    ]
    if not prompt_override:
        raise ValueError("firewall_threat agent requires a prompt — ensure Langfuse prompt 'first-light-firewall-threat' exists with label=production")
    system = prompt_override.format(hours=hours)
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

DNS_USER = "Analyse DNS security activity for the past {hours} hours."


def run_dns_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the DNS security domain agent."""
    from agent.tools.metrics import (
        query_adguard_network_summary,
        query_adguard_top_clients,
        query_adguard_block_rates,
        query_adguard_high_risk_clients,
        query_adguard_blocked_domains,
        query_adguard_traffic_by_type,
        query_adguard_dhcp_fingerprints,
        query_adguard_threat_signals,
        query_adguard_new_devices,
        query_adguard_blocklist_attribution,
    )

    tools = [
        query_adguard_network_summary,
        query_adguard_high_risk_clients,
        query_adguard_blocked_domains,
        query_adguard_dhcp_fingerprints,
        query_adguard_threat_signals,
        query_adguard_new_devices,
        query_adguard_blocklist_attribution,
        query_adguard_top_clients,
        query_adguard_traffic_by_type,
        query_adguard_block_rates,
    ]
    if not prompt_override:
        raise ValueError("dns agent requires a prompt — ensure Langfuse prompt 'first-light-dns' exists with label=production")
    system = prompt_override.format(hours=hours)
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
        query_ntopng_flows_by_host,
        query_ntopng_interfaces,
        query_ntopng_vlan_traffic,
        query_ntopng_top_countries,
        query_ntopng_arp_table,
    )
    from agent.tools.switch_tools import (
        query_switch_port_traffic,
        query_switch_port_errors,
        query_pfsense_interface_traffic,
    )
    from agent.tools.pfsense_dhcp import query_dhcp_device_inventory

    tools = [
        query_ntopng_alerts,
        query_ntopng_interface_stats,
        query_ntopng_vlan_traffic,
        query_ntopng_active_hosts,
        query_ntopng_l7_protocols,
        query_ntopng_top_countries,
        query_ntopng_active_flows,
        query_ntopng_flows_by_host,
        query_ntopng_interfaces,
        query_ntopng_arp_table,
        query_switch_port_traffic,
        query_switch_port_errors,
        query_pfsense_interface_traffic,
        query_dhcp_device_inventory,
    ]
    if not prompt_override:
        raise ValueError("network_flow agent requires a prompt — ensure Langfuse prompt 'first-light-network-flow' exists with label=production")
    system = prompt_override.format(hours=hours)
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

INFRASTRUCTURE_USER = "Analyse infrastructure health for the past {hours} hours."


def run_infrastructure_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the infrastructure health domain agent."""
    from agent.tools.logs import query_infrastructure_events
    from agent.tools.qnap_tools import query_qnap_health, query_qnap_events
    from agent.tools.proxmox_tools import query_proxmox_health
    from agent.tools.frigate import query_frigate_health, query_frigate_events
    from agent.tools.pbs import query_pbs_backup_status
    from agent.tools.uptime_kuma import (
        query_uptime_kuma_status,
        query_uptime_kuma_uptime,
        query_uptime_kuma_incidents,
    )

    from agent.tools.switch_tools import query_switch_port_errors, query_pfsense_interface_traffic
    tools = [
        query_infrastructure_events,
        query_qnap_health,
        query_qnap_events,
        query_proxmox_health,
        query_frigate_health,
        query_frigate_events,
        query_pbs_backup_status,
        query_uptime_kuma_status,
        query_uptime_kuma_uptime,
        query_uptime_kuma_incidents,
        query_switch_port_errors,
        query_pfsense_interface_traffic,
    ]
    if not prompt_override:
        raise ValueError("infrastructure agent requires a prompt — ensure Langfuse prompt 'first-light-infrastructure' exists with label=production")
    system = prompt_override.format(hours=hours)
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

WIRELESS_USER = "Analyse wireless network health for the past {hours} hours."


def run_wireless_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the wireless health domain agent."""
    from agent.tools.logs import query_wireless_health

    tools = [query_wireless_health]
    if not prompt_override:
        raise ValueError("wireless agent requires a prompt — ensure Langfuse prompt 'first-light-wireless' exists with label=production")
    system = prompt_override.format(hours=hours)
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

VALIDATOR_USER = "Analyse Ethereum validator health for the past {hours} hours."


def run_validator_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the Ethereum validator domain agent."""
    from agent.tools.validator import query_validator_health

    tools = [query_validator_health]
    if not prompt_override:
        raise ValueError("validator agent requires a prompt — ensure Langfuse prompt 'first-light-validator' exists with label=production")
    system = prompt_override.format(hours=hours)
    user = VALIDATOR_USER.format(hours=hours)

    logger.info("Running validator_agent...")
    try:
        return run_react_loop(system, user, tools, "validator", session_id=session_id)
    except Exception as e:
        logger.error(f"validator_agent failed: {e}", exc_info=True)
        return f"**Validator**: Agent failed — {e}"


# ─────────────────────────────────────────────
# Domain Agent: Cloudflare Edge Security
# ─────────────────────────────────────────────

CLOUDFLARE_USER = "Analyse Cloudflare edge security and external exposure for the past {hours} hours."


def run_cloudflare_agent(
    hours: int = 24,
    prompt_override: str = "",
    session_id: Optional[str] = None,
) -> str:
    """Run the Cloudflare edge security domain agent."""
    from agent.tools.cloudflare_tools import (
        query_cloudflare_waf_events,
        query_cloudflare_gateway_dns,
        query_cloudflare_zone_analytics,
        query_cloudflare_dns_analytics,
    )

    tools = [
        query_cloudflare_waf_events,
        query_cloudflare_dns_analytics,
        query_cloudflare_gateway_dns,
        query_cloudflare_zone_analytics,
    ]
    if not prompt_override:
        raise ValueError("cloudflare agent requires a prompt — ensure Langfuse prompt 'first-light-cloudflare' exists with label=production")
    system = prompt_override.format(hours=hours)
    user = CLOUDFLARE_USER.format(hours=hours)

    logger.info("Running cloudflare_agent...")
    try:
        return run_react_loop(system, user, tools, "cloudflare", session_id=session_id)
    except Exception as e:
        logger.error(f"cloudflare_agent failed: {e}", exc_info=True)
        return f"**Cloudflare**: Agent failed — {e}"
