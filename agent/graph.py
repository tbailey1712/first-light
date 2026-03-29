"""
First Light AI Agent — interactive query entrypoint.

create_system_prompt() builds the topology-aware system prompt used by both
the daily report pipeline and the interactive Telegram bot.

run_interactive_query() will be implemented in Sprint 3 (S3-01) once the
Telegram bot and Redis conversation history are in place.
"""

from agent.config import get_config, load_topology
from agent.tools.metrics import (
    query_adguard_top_clients,
    query_adguard_block_rates,
    query_adguard_high_risk_clients,
    query_adguard_blocked_domains,
    query_adguard_traffic_by_type,
)
from agent.tools.logs import (
    query_security_summary,
    query_wireless_health,
    query_infrastructure_events,
    search_logs_by_ip,
)
from agent.tools.threat_intel_tools import (
    query_threat_intel_summary,
    lookup_ip_threat_intel,
    query_threat_intel_coverage,
)
from agent.tools.qnap_tools import query_qnap_health, query_qnap_directory_sizes
from agent.tools.proxmox_tools import query_proxmox_health


# Full tool set available to the interactive agent (Sprint 3 adds validator + qnap directory)
INTERACTIVE_TOOLS = [
    query_adguard_top_clients,
    query_adguard_block_rates,
    query_adguard_high_risk_clients,
    query_adguard_blocked_domains,
    query_adguard_traffic_by_type,
    query_security_summary,
    query_wireless_health,
    query_infrastructure_events,
    search_logs_by_ip,
    query_threat_intel_summary,
    lookup_ip_threat_intel,
    query_threat_intel_coverage,
    query_qnap_health,
    query_qnap_directory_sizes,
    query_proxmox_health,
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
- **AdGuard DNS**: Query metrics, block rates, high-risk clients, blocked domains, traffic types
- **Security Logs**: pfSense firewall blocks, ntopng security alerts (query_security_summary)
- **Wireless Health**: UniFi deauth events, client anomalies, roaming issues (query_wireless_health)
- **Infrastructure**: Docker health checks, Home Assistant errors, Proxmox operations (query_infrastructure_events)
- **IP Investigation**: Search all logs for a specific IP address (search_logs_by_ip)
- **Hardware Health**: query_qnap_health (NAS volumes/disks/temps), query_proxmox_health (VMs/containers/storage)
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
