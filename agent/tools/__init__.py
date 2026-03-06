"""
First Light Agent Tools

Tools for querying various network data sources.
"""

from typing import List
from langchain_core.tools import BaseTool

from agent.tools.logs import (
    query_security_summary,
    query_adguard_anomalies,
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


def get_all_tools() -> List[BaseTool]:
    """Get all available tools for the agent."""
    tools = [
        # Log query tools
        query_security_summary,
        query_adguard_anomalies,
        query_wireless_health,
        query_infrastructure_events,
        search_logs_by_ip,
        # Metrics query tools
        query_adguard_top_clients,
        query_adguard_block_rates,
        query_adguard_high_risk_clients,
        query_adguard_blocked_domains,
        query_adguard_traffic_by_type,
    ]
    return tools
