"""
DNS Security Domain Graph

LangGraph with parallel micro-agent execution using concurrent.futures.
Compatible with LangGraph 1.0.5+
"""

from typing import Literal
from concurrent.futures import ThreadPoolExecutor, as_completed
from langgraph.graph import StateGraph, START, END
from langgraph.graph.state import CompiledStateGraph

from agent.state import AgentState, MicroAgentInput, MicroAgentOutput
from agent.agent_factory import get_agent_factory
from agent.tools import get_all_tools
from agent.domains.dns_security import create_dns_micro_agent_inputs, execute_dns_supervisor


# === Node Functions ===

def execute_agents_parallel(state: AgentState) -> dict:
    """
    Execute all 5 DNS micro-agents in parallel using ThreadPoolExecutor.

    This provides true parallelization without requiring Send API.
    """
    print("📋 Preparing and executing DNS micro-agents in parallel...")

    # Create agent inputs
    agent_inputs = create_dns_micro_agent_inputs(state.time_range_hours)

    factory = get_agent_factory()
    tools = get_all_tools()

    def execute_single_agent(agent_input: MicroAgentInput) -> MicroAgentOutput:
        """Execute a single agent (runs in thread)."""
        print(f"  🤖 Executing {agent_input.agent_type}...")
        output = factory.create_micro_agent(agent_input, tools)
        print(f"    ✓ {agent_input.agent_type}: {output.status}, {len(output.findings)} findings")
        return output

    # Execute agents in parallel
    outputs = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Submit all agents
        future_to_input = {
            executor.submit(execute_single_agent, agent_input): agent_input
            for agent_input in agent_inputs
        }

        # Collect results as they complete
        for future in as_completed(future_to_input):
            try:
                output = future.result()
                outputs.append(output)
            except Exception as e:
                agent_input = future_to_input[future]
                print(f"    ✗ {agent_input.agent_type} failed: {e}")
                # Create failed output
                outputs.append(MicroAgentOutput(
                    agent_id=agent_input.agent_id,
                    agent_type=agent_input.agent_type,
                    domain=agent_input.domain,
                    status="failed",
                    error_message=str(e),
                    findings=[],
                    summary=f"Agent failed: {str(e)}"
                ))

    successful = len([o for o in outputs if o.status == "success"])
    print(f"\n📊 Parallel execution complete: {successful}/{len(outputs)} agents succeeded")

    return {
        "micro_agent_outputs": outputs
    }


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
    1. START → execute_agents_parallel: Run all 5 agents in parallel (ThreadPoolExecutor)
    2. execute_agents_parallel → run_supervisor: Generate domain summary
    3. run_supervisor → END

    Returns:
        Compiled StateGraph ready for execution
    """
    # Create graph
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("execute_agents_parallel", execute_agents_parallel)
    graph.add_node("run_supervisor", run_supervisor)

    # Add edges
    graph.add_edge(START, "execute_agents_parallel")
    graph.add_edge("execute_agents_parallel", "run_supervisor")
    graph.add_edge("run_supervisor", END)

    # Compile
    return graph.compile()


# === Main Entry Point ===

def analyze_dns_security_parallel(time_range_hours: int = 24) -> dict:
    """
    Run DNS security analysis with parallel agent execution.

    Uses ThreadPoolExecutor for true parallelization compatible with LangGraph 1.0.5+

    Args:
        time_range_hours: Lookback period for analysis

    Returns:
        Final state dict with supervisor outputs, total_findings, etc.
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
    if result.get("supervisor_outputs"):
        print(result["supervisor_outputs"][0].domain_summary)
    print(f"\nTotal findings: {result.get('total_findings', 0)}")
