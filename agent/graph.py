"""
First Light AI Agent - LangGraph implementation.

A ReAct-style agent that queries network observability data and provides analysis.
"""

from typing import Annotated, Literal

from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage, SystemMessage
from langgraph.graph import StateGraph, MessagesState, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver

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

When analyzing:
1. Start with security_summary for recent threats
2. Use wireless_health to check WiFi stability
3. Use infrastructure_events to verify service health
4. Use search_logs_by_ip to investigate suspicious IPs
5. Cross-reference AdGuard DNS data with firewall blocks

Always query tools to gather current data. Don't rely on assumptions or cached knowledge.

Be concise but thorough. Network operators appreciate brevity with substance.
"""


def create_agent():
    """Create the First Light agent graph."""
    config = get_config()

    # Initialize LLM via LiteLLM router
    llm = ChatOpenAI(
        model=config.litellm_model,
        api_key=config.litellm_api_key or "dummy-key",  # LiteLLM may not require auth
        base_url=config.litellm_base_url,
        temperature=0.1,
    )

    # Bind tools to LLM
    tools = [
        # AdGuard DNS metrics
        query_adguard_top_clients,
        query_adguard_block_rates,
        query_adguard_high_risk_clients,
        query_adguard_blocked_domains,
        query_adguard_traffic_by_type,
        # Security & Infrastructure logs
        query_security_summary,
        query_wireless_health,
        query_infrastructure_events,
        search_logs_by_ip,
    ]
    llm_with_tools = llm.bind_tools(tools)

    # System message
    system_message = SystemMessage(content=create_system_prompt())

    def call_model(state: MessagesState):
        """Call the LLM with tools."""
        messages = [system_message] + state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    # Build graph
    graph_builder = StateGraph(MessagesState)

    # Add nodes
    graph_builder.add_node("agent", call_model)
    graph_builder.add_node("tools", ToolNode(tools))

    # Add edges
    graph_builder.add_edge(START, "agent")
    graph_builder.add_conditional_edges(
        "agent",
        tools_condition,
    )
    graph_builder.add_edge("tools", "agent")

    # Compile with checkpointer for conversation memory
    checkpointer = MemorySaver()
    graph = graph_builder.compile(checkpointer=checkpointer)

    return graph


# Global agent instance
_agent = None


def get_agent():
    """Get or create the agent instance."""
    global _agent
    if _agent is None:
        _agent = create_agent()
    return _agent
