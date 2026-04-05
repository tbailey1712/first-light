"""
First Light AI Agent — interactive query entrypoint.

create_system_prompt() builds the topology-aware system prompt used by both
the daily report pipeline and the interactive Telegram bot.

run_interactive_query() drives the interactive bot experience: it accepts
a user question plus conversation history and returns an answer string by
running the full ReAct loop against INTERACTIVE_TOOLS.
"""

import asyncio
import logging
from typing import Optional

from agent.config import get_config, load_topology

logger = logging.getLogger(__name__)
from agent.tools.metrics import (
    query_adguard_top_clients,
    query_adguard_block_rates,
    query_adguard_high_risk_clients,
    query_adguard_blocked_domains,
    query_adguard_traffic_by_type,
    query_adguard_network_summary,
    query_adguard_dhcp_fingerprints,
    query_adguard_threat_signals,
    query_adguard_new_devices,
    query_adguard_blocklist_attribution,
)
from agent.tools.logs import (
    query_security_summary,
    query_wireless_health,
    query_infrastructure_events,
    search_logs_by_ip,
    search_logs_by_hostname,
)
from agent.tools.threat_intel_tools import (
    query_threat_intel_summary,
    lookup_ip_threat_intel,
    query_threat_intel_coverage,
)
from agent.tools.qnap_tools import query_qnap_health, query_qnap_directory_sizes
from agent.tools.proxmox_tools import query_proxmox_health, query_proxmox_vm_configs
from agent.tools.dns_tools import resolve_hostname, resolve_multiple_hostnames, reverse_lookup_ip
from agent.tools.crowdsec import query_crowdsec_metrics
from agent.tools.cloudflare_tools import query_cloudflare_dns_records, query_cloudflare_access_apps
from agent.tools.pbs import query_pbs_backup_status, query_pbs_prune_policies
from agent.tools.switch_tools import query_switch_port_status
from agent.tools.validator import query_validator_node_config
from agent.tools.uptime_kuma import query_uptime_kuma_monitors
from agent.tools.unifi_tools import query_unifi_clients, query_unifi_ap_stats, lookup_unifi_client_by_mac
from agent.tools.ntopng import (
    query_ntopng_active_hosts,
    query_ntopng_alerts,
    query_ntopng_flows_by_host,
    query_ntopng_l7_protocols,
    query_ntopng_top_countries,
    query_ntopng_host_details,
)


# Full tool set available to the interactive agent
INTERACTIVE_TOOLS = [
    # AdGuard DNS (via ClickHouse metrics)
    query_adguard_top_clients,
    query_adguard_block_rates,
    query_adguard_high_risk_clients,
    query_adguard_blocked_domains,
    query_adguard_traffic_by_type,
    query_adguard_network_summary,
    query_adguard_dhcp_fingerprints,
    query_adguard_threat_signals,
    query_adguard_new_devices,
    query_adguard_blocklist_attribution,
    # Logs — security, wireless, infrastructure
    query_security_summary,
    query_wireless_health,
    query_infrastructure_events,
    search_logs_by_ip,
    search_logs_by_hostname,
    # Threat intelligence
    query_threat_intel_summary,
    lookup_ip_threat_intel,
    query_threat_intel_coverage,
    # Hardware & infrastructure
    query_qnap_health,
    query_qnap_directory_sizes,
    query_proxmox_health,
    query_proxmox_vm_configs,
    # Backup & storage
    query_pbs_backup_status,
    query_pbs_prune_policies,
    # Network services
    query_crowdsec_metrics,
    query_cloudflare_dns_records,
    query_cloudflare_access_apps,
    query_switch_port_status,
    query_uptime_kuma_monitors,
    # Validator
    query_validator_node_config,
    # DNS resolution
    resolve_hostname,
    resolve_multiple_hostnames,
    reverse_lookup_ip,
    # UniFi Controller
    query_unifi_clients,
    query_unifi_ap_stats,
    lookup_unifi_client_by_mac,
    # ntopng flow analysis
    query_ntopng_active_hosts,
    query_ntopng_alerts,
    query_ntopng_flows_by_host,
    query_ntopng_l7_protocols,
    query_ntopng_top_countries,
    query_ntopng_host_details,
]


def create_system_prompt() -> str:
    """Generate system prompt with network topology context."""
    config = get_config()
    topology = load_topology()

    # Summarize network topology
    vlans = topology.get("network", {}).get("vlans", [])
    vlan_summary = "\n".join([
        f"  - VLAN {v['id']} ({v['name']}): {v['purpose']} - Security: {v['security_level']}"
        for v in vlans
    ])

    devices = topology.get("devices", {})
    device_summary = "\n".join([
        f"  - {name.title()}: {info.get('hostname', 'N/A')} - {info.get('type', 'unknown')}"
        for name, info in devices.items()
    ])

    monitoring_focus = topology.get("monitoring_focus", {})
    security_focus = "\n".join([f"  - {item}" for item in monitoring_focus.get("security", [])])

    return f"""You are First Light AI, a network security and infrastructure analyst for a home/prosumer network.

# Network Topology

## VLANs:
{vlan_summary}

## Devices:
{device_summary}

# Your Role

You monitor and analyze:
1. **Security**: Firewall blocks, DNS filtering, intrusion attempts, anomalous traffic
2. **Infrastructure Health**: Disk space, CPU/memory, service availability
3. **Network Performance**: Bandwidth utilization, top talkers, errors
4. **Ethereum Validator**: Attestation effectiveness, sync status, balance

# Security Priorities

{security_focus}

# Analysis Guidelines

- **Be specific**: Include IPs, timestamps, affected VLANs, exact counts
- **Correlate events**: Connect patterns across data sources (e.g., DNS blocks + firewall blocks from same IP)
- **Severity levels**:
  - CRITICAL: Active threats, service down, validator offline, disk full
  - WARNING: Unusual patterns, degraded performance, approaching thresholds
  - INFO: Normal operations, routine summaries, positive confirmations
- **Actionable recommendations**: Suggest concrete next steps, not generic advice

# Available Tools

You have tools to query:
- **AdGuard DNS**: query_adguard_top_clients, query_adguard_block_rates, query_adguard_high_risk_clients, query_adguard_blocked_domains, query_adguard_traffic_by_type, query_adguard_network_summary (full DNS summary), query_adguard_dhcp_fingerprints (per-device top domains for device ID — e.g. ring.com → Ring camera), query_adguard_threat_signals (beaconing scores, TXT tunneling ratios, anomaly counts), query_adguard_new_devices (first-seen clients), query_adguard_blocklist_attribution (which blocklists are hitting)
- **Security Logs**: pfSense firewall blocks, ntopng security alerts (query_security_summary)
- **ntopng Flow Analysis**: query_ntopng_active_hosts (top talkers by traffic), query_ntopng_alerts (IDS/flow alerts), query_ntopng_flows_by_host (per-IP flow details), query_ntopng_l7_protocols (application breakdown), query_ntopng_top_countries (geo traffic distribution), query_ntopng_host_details (per-IP reputation and stats)
- **Wireless Health**: UniFi deauth events, client anomalies, roaming issues (query_wireless_health)
- **Infrastructure**: Docker health checks, Home Assistant errors, Proxmox operations (query_infrastructure_events)
- **IP Investigation**: Search all logs for a specific IP address (search_logs_by_ip)
- **Hardware Health**: query_qnap_health (NAS volumes/disks/temps), query_proxmox_health (VMs/containers/storage), query_proxmox_vm_configs (detailed VM/CT config + backup job coverage)
- **Backup**: query_pbs_backup_status (last backup per VM, stale/failed tasks), query_pbs_prune_policies (retention schedules per datastore)
- **Network Services**: query_crowdsec_metrics (active decisions, alerts, parser hit rates), query_cloudflare_dns_records (all DNS records for mcducklabs.com), query_cloudflare_access_apps (Zero Trust Access apps), query_switch_port_status (port operational state and traffic), query_uptime_kuma_monitors (monitor status and notification config)
- **Validator**: query_validator_node_config (Nimbus sync status, peer count, fee recipient, bloXroute BDN check)
- **DNS**: resolve_hostname / resolve_multiple_hostnames — verify hostname resolution via system DNS (AdGuard)
- **Threat Intelligence**: Enriched IP reputation from AbuseIPDB, VirusTotal, AlienVault:
  - query_threat_intel_summary(hours, min_score) — blocked IPs joined with threat scores, sorted by severity
  - lookup_ip_threat_intel(ip) — full reputation profile for a specific IP
  - query_threat_intel_coverage() — how many blocked IPs have been enriched

When analyzing security:
1. Call query_threat_intel_summary(hours=24) — this is the highest signal view, showing confirmed malicious IPs hitting the firewall
2. Call query_security_summary(hours=24) for raw firewall and ntopng context
3. For any high-scoring IPs (threat_score > 50), call lookup_ip_threat_intel for full details
4. Use wireless_health and infrastructure_events for non-security health checks
5. Cross-reference AdGuard DNS data with firewall block patterns

Threat score interpretation:
- 0-25: Low risk, likely benign scanner or crawler
- 25-50: Moderate risk, monitor
- 50-75: High risk, known bad actor
- 75-100: Confirmed malicious, immediate attention warranted

Always query tools to gather current data. Don't rely on assumptions or cached knowledge.

Be concise but thorough. Network operators appreciate brevity with substance.
"""


def run_interactive_query_sync(
    question: str,
    history: Optional[list[dict]] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    Synchronous interactive query — runs the ReAct loop with the full tool set.

    Args:
        question:   The user's question or request.
        history:    Optional prior conversation turns as OpenAI-format messages
                    [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}, ...]
                    The question is appended as the final user turn.
        session_id: Groups Langfuse traces under one session (e.g. Telegram chat_id).

    Returns:
        Answer string from the agent.
    """
    from agent.llm import run_react_loop

    system_prompt = create_system_prompt()

    # Build a user prompt that includes condensed history if provided
    if history:
        history_text = "\n".join(
            f"{m['role'].upper()}: {m['content']}"
            for m in history[-10:]  # last 10 turns to avoid context overflow
            if m.get("content")
        )
        user_prompt = f"Conversation history:\n{history_text}\n\nCurrent question: {question}"
    else:
        user_prompt = question

    return run_react_loop(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        tools=INTERACTIVE_TOOLS,
        agent_name="interactive",
        agent_type="micro",
        session_id=session_id,
    )


async def run_interactive_query(
    question: str,
    history: Optional[list[dict]] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    Async interactive query — wraps the synchronous ReAct loop in a thread
    so it doesn't block the asyncio event loop used by the Telegram/Slack bots.

    Args:
        question:   The user's question or request.
        history:    Optional prior conversation turns (OpenAI message format).
        session_id: Groups Langfuse traces under one session.

    Returns:
        Answer string from the agent.
    """
    return await asyncio.get_running_loop().run_in_executor(
        None,
        run_interactive_query_sync,
        question,
        history,
        session_id,
    )
