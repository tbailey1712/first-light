"""
DNS Security Domain - Micro-agents and Supervisor

Contains 5 specialized micro-agents for DNS security analysis:
1. dns_block_rate_analyzer - Device-aware block rate analysis
2. dns_anomaly_detector - DGA, tunneling, exfiltration detection
3. dns_threat_intel - Threat feed correlation
4. dns_query_pattern - Query pattern analysis
5. dns_client_risk - Composite client risk scoring

Plus: dns_security_supervisor - Aggregates findings from all 5 agents
"""

from typing import List
from datetime import datetime

from agent.state import MicroAgentInput, MicroAgentOutput, SupervisorInput, SupervisorOutput
from agent.agent_factory import get_agent_factory
from agent.tools import get_all_tools


def create_dns_micro_agent_inputs(time_range_hours: int = 24) -> List[MicroAgentInput]:
    """
    Create input specs for all 5 DNS security micro-agents.

    Args:
        time_range_hours: Lookback period for analysis

    Returns:
        List of MicroAgentInput for parallel execution
    """
    return [
        MicroAgentInput(
            agent_id="dns_block_rate_001",
            agent_type="dns_block_rate_analyzer",
            domain="dns_security",
            time_range_hours=time_range_hours,
            parameters={}
        ),
        MicroAgentInput(
            agent_id="dns_anomaly_002",
            agent_type="dns_anomaly_detector",
            domain="dns_security",
            time_range_hours=time_range_hours,
            parameters={"min_severity": "medium"}
        ),
        MicroAgentInput(
            agent_id="dns_threat_intel_003",
            agent_type="dns_threat_intel",
            domain="dns_security",
            time_range_hours=time_range_hours,
            parameters={}
        ),
        MicroAgentInput(
            agent_id="dns_query_pattern_004",
            agent_type="dns_query_pattern",
            domain="dns_security",
            time_range_hours=time_range_hours,
            parameters={}
        ),
        MicroAgentInput(
            agent_id="dns_client_risk_005",
            agent_type="dns_client_risk",
            domain="dns_security",
            time_range_hours=time_range_hours,
            parameters={}
        ),
    ]


def execute_dns_micro_agents(time_range_hours: int = 24) -> List[MicroAgentOutput]:
    """
    Execute all 5 DNS security micro-agents in parallel.

    Args:
        time_range_hours: Lookback period for analysis

    Returns:
        List of MicroAgentOutput from all agents
    """
    factory = get_agent_factory()
    tools = get_all_tools()

    # Get input specs
    agent_inputs = create_dns_micro_agent_inputs(time_range_hours)

    # Execute all agents (in serial for now, will parallelize in graph)
    outputs = []
    for agent_input in agent_inputs:
        print(f"Executing {agent_input.agent_type}...")
        output = factory.create_micro_agent(agent_input, tools)
        outputs.append(output)
        print(f"  Status: {output.status}, Findings: {len(output.findings)}")

    return outputs


def execute_dns_supervisor(micro_agent_outputs: List[MicroAgentOutput]) -> SupervisorOutput:
    """
    Execute DNS security domain supervisor.

    Aggregates findings from all 5 micro-agents and identifies correlations.

    Args:
        micro_agent_outputs: Results from all DNS micro-agents

    Returns:
        SupervisorOutput with aggregated analysis
    """
    factory = get_agent_factory()

    supervisor_input = SupervisorInput(
        supervisor_id="dns_security_supervisor_001",
        domain="dns_security",
        micro_agent_outputs=micro_agent_outputs
    )

    print("Executing DNS security supervisor...")
    output = factory.create_supervisor(supervisor_input)
    print(f"  Domain health score: {output.domain_health_score:.1f}/100")
    print(f"  Critical findings: {len(output.critical_findings)}")
    print(f"  High findings: {len(output.high_findings)}")
    print(f"  Correlations: {len(output.cross_agent_correlations)}")

    return output


def analyze_dns_security(time_range_hours: int = 24) -> SupervisorOutput:
    """
    Run full DNS security analysis: all 5 micro-agents + supervisor.

    This is the main entry point for DNS security domain analysis.

    Args:
        time_range_hours: Lookback period for analysis

    Returns:
        SupervisorOutput with complete DNS security assessment
    """
    print("=" * 80)
    print(f"DNS SECURITY ANALYSIS - {datetime.utcnow().isoformat()}Z")
    print("=" * 80)
    print()

    # Execute micro-agents
    print("Phase 1: Executing 5 DNS micro-agents...")
    print("-" * 80)
    micro_outputs = execute_dns_micro_agents(time_range_hours)
    print()

    # Execute supervisor
    print("Phase 2: Executing domain supervisor...")
    print("-" * 80)
    supervisor_output = execute_dns_supervisor(micro_outputs)
    print()

    print("=" * 80)
    print("DNS SECURITY ANALYSIS COMPLETE")
    print("=" * 80)

    return supervisor_output


if __name__ == "__main__":
    # Load environment
    from dotenv import load_dotenv
    load_dotenv()

    # Test execution
    result = analyze_dns_security(time_range_hours=24)

    print("\n" + "=" * 80)
    print("DOMAIN SUMMARY")
    print("=" * 80)
    print(result.domain_summary)
