"""
State schemas for hierarchical multi-agent system.

Defines the data structures passed between micro-agents, supervisors, and synthesis.
"""

from typing import List, Dict, Any, Literal, Optional, Annotated
from pydantic import BaseModel, Field
from datetime import datetime
import operator


class Finding(BaseModel):
    """A single security or operational finding from a micro-agent."""

    finding_id: str = Field(description="Unique identifier for this finding")
    agent_id: str = Field(description="ID of the agent that discovered this")
    domain: Literal["dns_security", "network_security", "infrastructure", "validator", "wireless"]
    severity: Literal["critical", "high", "medium", "low", "info"]

    title: str = Field(description="Short title (1 line)")
    description: str = Field(description="Detailed description with context")

    affected_systems: List[str] = Field(default_factory=list, description="IPs, hostnames, or device names")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting data (metrics, log samples)")

    confidence: float = Field(ge=0.0, le=1.0, description="Agent's confidence in this finding")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    recommendations: List[str] = Field(default_factory=list, description="Actionable next steps")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class MicroAgentOutput(BaseModel):
    """Output from a single micro-agent analysis."""

    agent_id: str
    agent_type: str = Field(description="e.g., 'dns_block_rate_analyzer'")
    domain: Literal["dns_security", "network_security", "infrastructure", "validator", "wireless"]

    status: Literal["success", "partial", "failed"]
    error_message: Optional[str] = None

    findings: List[Finding] = Field(default_factory=list)
    summary: str = Field(description="Brief summary of what this agent analyzed")

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Agent-specific metadata (query times, data sources used, etc.)"
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SupervisorOutput(BaseModel):
    """Output from a domain supervisor that aggregates micro-agent findings."""

    supervisor_id: str
    domain: Literal["dns_security", "network_security", "infrastructure", "validator", "wireless"]

    micro_agent_count: int = Field(description="Number of micro-agents analyzed")
    critical_findings: List[Finding] = Field(default_factory=list)
    high_findings: List[Finding] = Field(default_factory=list)
    medium_findings: List[Finding] = Field(default_factory=list)
    low_findings: List[Finding] = Field(default_factory=list)

    domain_summary: str = Field(description="Executive summary for this domain")
    cross_agent_correlations: List[str] = Field(
        default_factory=list,
        description="Patterns detected across multiple micro-agents"
    )

    domain_health_score: float = Field(
        ge=0.0, le=100.0,
        description="Overall health score for this domain (100 = perfect)"
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AgentState(BaseModel):
    """
    Root state for the hierarchical agent graph.

    Uses `operator.add` reducers for list fields to accumulate results from parallel agents.
    """

    # Analysis request
    analysis_type: Literal["scheduled_digest", "interactive_query", "incident_investigation"]
    time_range_hours: int = Field(default=24, description="Lookback period for analysis")
    specific_query: Optional[str] = Field(default=None, description="For interactive queries")

    # Micro-agent outputs (fan-out results)
    micro_agent_outputs: Annotated[List[MicroAgentOutput], operator.add] = Field(default_factory=list)

    # Supervisor outputs (domain aggregation)
    supervisor_outputs: Annotated[List[SupervisorOutput], operator.add] = Field(default_factory=list)

    # Final synthesis
    synthesis_report: Optional[str] = None
    synthesis_metadata: Dict[str, Any] = Field(default_factory=dict)

    # Execution metadata
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    total_findings: int = 0
    critical_count: int = 0

    # Error tracking
    errors: Annotated[List[str], operator.add] = Field(default_factory=list)

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class MicroAgentInput(BaseModel):
    """Input specification for launching a micro-agent."""

    agent_id: str
    agent_type: str
    domain: Literal["dns_security", "network_security", "infrastructure", "validator", "wireless"]
    time_range_hours: int

    # Specific parameters per agent type
    parameters: Dict[str, Any] = Field(default_factory=dict)


class SupervisorInput(BaseModel):
    """Input specification for launching a domain supervisor."""

    supervisor_id: str
    domain: Literal["dns_security", "network_security", "infrastructure", "validator", "wireless"]
    micro_agent_outputs: List[MicroAgentOutput]
