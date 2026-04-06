"""
First Light Agent Tools

Tools for querying various network data sources.
"""

from typing import List
from langchain_core.tools import BaseTool

from agent.tools.logs import (
    query_security_summary,
    query_wireless_health,
    query_infrastructure_events,
    search_logs_by_ip,
)

from agent.tools.metrics import (
    query_adguard_top_clients,
    query_adguard_block_rates,
    query_adguard_high_risk_clients,
    query_adguard_blocked_domains,
    query_adguard_traffic_by_type,
)

from agent.tools.threat_intel_tools import (
    query_threat_intel_summary,
    lookup_ip_threat_intel,
    query_threat_intel_coverage,
)

from agent.tools.qnap_tools import query_qnap_health, query_qnap_directory_sizes
from agent.tools.proxmox_tools import query_proxmox_health, query_proxmox_trends

from agent.tools.switch_tools import (
    query_switch_port_traffic,
    query_switch_port_errors,
    query_switch_port_status,
    query_switch_events,
    query_pfsense_interface_traffic,
)

from agent.tools.validator import (
    query_validator_health,
    query_validator_node_config,
)

from agent.tools.ha_tools import (
    query_ha_logbook,
    query_ha_entity_states,
    query_ha_entity_history,
)


def get_all_tools() -> List[BaseTool]:
    """Get all available tools for the agent."""
    return [
        # Log query tools
        query_security_summary,
        query_wireless_health,
        query_infrastructure_events,
        search_logs_by_ip,
        # Metrics query tools
        query_adguard_top_clients,
        query_adguard_block_rates,
        query_adguard_high_risk_clients,
        query_adguard_blocked_domains,
        query_adguard_traffic_by_type,
        # Threat intelligence
        query_threat_intel_summary,
        lookup_ip_threat_intel,
        query_threat_intel_coverage,
        # Hardware health
        query_qnap_health,
        query_qnap_directory_sizes,
        query_proxmox_health,
        # Switch and firewall interface stats (TOOL-12)
        query_switch_port_traffic,
        query_switch_port_errors,
        query_switch_port_status,
        query_pfsense_interface_traffic,
        # Ethereum validator (TOOL-13)
        query_validator_health,
        query_validator_node_config,
    ]
