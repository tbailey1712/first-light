"""
DNS Security Domain Graph

LangGraph with Send API for parallel micro-agent execution.
"""

from typing import Literal
from langgraph.graph import StateGraph, START, END, Send
from langgraph.graph.state import CompiledStateGraph

from agent.state import AgentState, MicroAgentInput, MicroAgentOutput
from agent.agent_factory import get_agent_factory
from agent.tools import get_all_tools
from agent.domains.dns_security import create_dns_micro_agent_inputs, execute_dns_supervisor


# === Node Functions ===

def prepare_agents(state: AgentState) -> dict:
    """
    Entry node: Prepare input specs for all 5 DNS micro-agents.

    This node creates MicroAgentInput specs that will be fanned out
    to parallel agent executions.
    """
    print("📋 Preparing DNS micro-agent inputs...")

    agent_inputs = create_dns_micro_agent_inputs(state.time_range_hours)

    return {
        "micro_agent_inputs": agent_inputs
    }


def fan_out_agents(state: AgentState) -> list[Send]:
    """
    Fan-out node: Send each agent input to parallel execution.

    Uses LangGraph Send API to launch all 5 agents concurrently.
    """
    print(f"🌐 Fanning out {len(state.micro_agent_inputs)} agents for parallel execution...")

    # Create Send commands for each agent
    sends = []
    for agent_input in state.micro_agent_inputs:
        sends.append(
            Send("execute_micro_agent", {"agent_input": agent_input})
        )

    return sends


def execute_micro_agent(state: dict) -> dict:
    """
    Agent execution node: Execute a single micro-agent.

    This node runs in parallel for each agent (via Send API).

    Args:
        state: Contains single agent_input

    Returns:
        Dict with micro_agent_outputs list (will be accumulated via operator.add)
    """
    agent_input: MicroAgentInput = state["agent_input"]

    print(f"  🤖 Executing {agent_input.agent_type}...")

    factory = get_agent_factory()
    tools = get_all_tools()

    output = factory.create_micro_agent(agent_input, tools)

    print(f"    ✓ {agent_input.agent_type}: {output.status}, {len(output.findings)} findings")

    return {
        "micro_agent_outputs": [output]  # Wrapped in list for operator.add
    }


def aggregate_results(state: AgentState) -> dict:
    """
    Aggregation checkpoint: Verify all agents completed.

    At this point, all micro-agent outputs have been accumulated
    via the operator.add reducer on AgentState.micro_agent_outputs.
    """
    total = len(state.micro_agent_outputs)
    successful = len([o for o in state.micro_agent_outputs if o.status == "success"])

    print(f"\n📊 Aggregation complete: {successful}/{total} agents succeeded")

    return {}  # State already has accumulated outputs


def run_supervisor(state: AgentState) -> dict:
    """
    Supervisor node: Aggregate findings and generate domain summary.
    """
    print(f"\n👔 Running DNS security supervisor...")

    supervisor_output = execute_dns_supervisor(state.micro_agent_outputs)

    # Count total findings
    total_findings = (
        len(supervisor_output.critical_findings) +
        len(supervisor_output.high_findings) +
        len(supervisor_output.medium_findings) +
        len(supervisor_output.low_findings)
    )

    print(f"   ✓ Domain health: {supervisor_output.domain_health_score:.1f}/100")
    print(f"   ✓ Total findings: {total_findings}")
    print(f"   ✓ Correlations: {len(supervisor_output.cross_agent_correlations)}")

    return {
        "supervisor_outputs": [supervisor_output],
        "total_findings": total_findings,
        "critical_count": len(supervisor_output.critical_findings),
        "end_time": supervisor_output.critical_findings[0].timestamp if supervisor_output.critical_findings else None
    }


# === Graph Construction ===

def create_dns_security_graph() -> CompiledStateGraph:
    """
    Create the DNS Security domain graph with parallel agent execution.

    Graph flow:
    1. START → prepare_agents: Create agent input specs
    2. prepare_agents → fan_out_agents: Fan out to parallel execution
    3. fan_out_agents → [execute_micro_agent × 5]: Run agents in parallel
    4. execute_micro_agent → aggregate_results: Collect results
    5. aggregate_results → run_supervisor: Generate domain summary
    6. run_supervisor → END

    Returns:
        Compiled StateGraph ready for execution
    """
    # Create graph
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("prepare_agents", prepare_agents)
    graph.add_node("execute_micro_agent", execute_micro_agent)
    graph.add_node("aggregate_results", aggregate_results)
    graph.add_node("run_supervisor", run_supervisor)

    # Add edges
    graph.add_edge(START, "prepare_agents")

    # Fan-out: prepare_agents sends to multiple execute_micro_agent calls
    graph.add_conditional_edges(
        "prepare_agents",
        fan_out_agents,  # Returns list of Send objects
        ["execute_micro_agent"]
    )

    # Fan-in: all execute_micro_agent outputs go to aggregate_results
    graph.add_edge("execute_micro_agent", "aggregate_results")

    # Supervisor and end
    graph.add_edge("aggregate_results", "run_supervisor")
    graph.add_edge("run_supervisor", END)

    # Compile
    return graph.compile()


# === Main Entry Point ===

def analyze_dns_security_parallel(time_range_hours: int = 24) -> AgentState:
    """
    Run DNS security analysis with parallel agent execution.

    This is the main entry point using the LangGraph with Send API.

    Args:
        time_range_hours: Lookback period for analysis

    Returns:
        Final AgentState with supervisor outputs
    """
    from datetime import datetime

    print("=" * 80)
    print(f"DNS SECURITY ANALYSIS (PARALLEL) - {datetime.utcnow().isoformat()}Z")
    print("=" * 80)
    print()

    # Create graph
    graph = create_dns_security_graph()

    # Initial state
    initial_state = AgentState(
        analysis_type="scheduled_digest",
        time_range_hours=time_range_hours,
        micro_agent_inputs=[]  # Will be populated by prepare_agents
    )

    # Execute graph
    final_state = graph.invoke(initial_state)

    print()
    print("=" * 80)
    print("DNS SECURITY ANALYSIS COMPLETE")
    print("=" * 80)

    return final_state


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    # Test execution
    result = analyze_dns_security_parallel(time_range_hours=24)

    print("\n" + "=" * 80)
    print("DOMAIN SUMMARY")
    print("=" * 80)
    if result.supervisor_outputs:
        print(result.supervisor_outputs[0].domain_summary)
    print(f"\nTotal findings: {result.total_findings}")
