"""
Agent factory for creating micro-agents, supervisors, and synthesis agents.

Uses model_config for model selection and Langfuse for prompt versioning.
"""

from typing import Literal, Dict, Any, Callable, List
from functools import lru_cache

from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import BaseTool
from langchain_core.messages import HumanMessage

from agent.model_config import create_llm_for_agent_type
from agent.langfuse_integration import get_agent_prompt, trace_agent
from agent.state import MicroAgentInput, MicroAgentOutput, SupervisorInput, SupervisorOutput, Finding


class AgentFactory:
    """Factory for creating configured agent instances."""

    def __init__(self):
        self.micro_agent_registry: Dict[str, Callable] = {}
        self.supervisor_registry: Dict[str, Callable] = {}

    def create_micro_agent_llm(self, **kwargs) -> BaseChatModel:
        """Create LLM configured for micro-agents (Claude Sonnet 4.5)."""
        return create_llm_for_agent_type("micro", **kwargs)

    def create_supervisor_llm(self, **kwargs) -> BaseChatModel:
        """Create LLM configured for supervisors (Claude Opus 4.6)."""
        return create_llm_for_agent_type("supervisor", **kwargs)

    def create_synthesis_llm(self, **kwargs) -> BaseChatModel:
        """Create LLM configured for synthesis (Claude Opus 4.6)."""
        return create_llm_for_agent_type("synthesis", **kwargs)

    def register_micro_agent(
        self,
        agent_type: str,
        agent_func: Callable[[MicroAgentInput, List[BaseTool]], MicroAgentOutput]
    ):
        """
        Register a micro-agent implementation.

        Args:
            agent_type: Unique agent type identifier
            agent_func: Function that takes MicroAgentInput and tools, returns MicroAgentOutput
        """
        self.micro_agent_registry[agent_type] = agent_func

    def register_supervisor(
        self,
        domain: str,
        supervisor_func: Callable[[SupervisorInput], SupervisorOutput]
    ):
        """
        Register a domain supervisor implementation.

        Args:
            domain: Domain name (dns_security, network_security, etc.)
            supervisor_func: Function that takes SupervisorInput and returns SupervisorOutput
        """
        self.supervisor_registry[domain] = supervisor_func

    def create_micro_agent(
        self,
        agent_input: MicroAgentInput,
        tools: List[BaseTool]
    ) -> MicroAgentOutput:
        """
        Create and execute a micro-agent.

        Args:
            agent_input: Input specification for the agent
            tools: Tools to bind to the agent

        Returns:
            MicroAgentOutput with findings
        """
        # Check if we have a registered implementation
        if agent_input.agent_type in self.micro_agent_registry:
            agent_func = self.micro_agent_registry[agent_input.agent_type]
            return agent_func(agent_input, tools)

        # Otherwise, use generic prompt-based agent
        return self._create_generic_micro_agent(agent_input, tools)

    def _create_generic_micro_agent(
        self,
        agent_input: MicroAgentInput,
        tools: List[BaseTool]
    ) -> MicroAgentOutput:
        """
        Create a generic prompt-based micro-agent.

        This is used when no specialized implementation is registered.
        """
        # Get versioned prompt from Langfuse (with fallback)
        system_prompt = get_agent_prompt(agent_input.agent_type)

        # Create LLM
        llm = self.create_micro_agent_llm()

        # Bind tools
        llm_with_tools = llm.bind_tools(tools)

        # Create user message
        user_message = f"""Analyze the network data for the past {agent_input.time_range_hours} hours.

Additional Parameters:
{agent_input.parameters if agent_input.parameters else 'None'}

Use the available tools to query data and analyze findings. Return your results as a JSON object with this structure:

{{
  "findings": [
    {{
      "finding_id": "unique_id",
      "severity": "critical|high|medium|low|info",
      "title": "Short title",
      "description": "Detailed description with context",
      "affected_systems": ["ip or hostname"],
      "evidence": {{}},
      "confidence": 0.0-1.0,
      "recommendations": ["actionable steps"]
    }}
  ],
  "summary": "Brief summary of analysis"
}}
"""

        try:
            # Execute agent with tools
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]

            response = llm_with_tools.invoke(messages)

            # Check if tool calls are needed
            tool_call_count = 0
            max_iterations = 10

            while hasattr(response, 'tool_calls') and response.tool_calls and tool_call_count < max_iterations:
                tool_call_count += 1

                # Execute tool calls
                messages.append(response)

                for tool_call in response.tool_calls:
                    # Find and execute the tool
                    tool = next((t for t in tools if t.name == tool_call['name']), None)
                    if tool:
                        tool_result = tool.invoke(tool_call['args'])
                        messages.append({
                            "role": "tool",
                            "content": str(tool_result),
                            "tool_call_id": tool_call['id']
                        })

                # Get next response
                response = llm_with_tools.invoke(messages)

            # Parse final response
            import json
            import re

            # Extract JSON from response (might be in markdown code block)
            content = response.content
            json_match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find raw JSON
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    # No valid JSON found
                    return MicroAgentOutput(
                        agent_id=agent_input.agent_id,
                        agent_type=agent_input.agent_type,
                        domain=agent_input.domain,
                        status="partial",
                        error_message="Could not parse JSON output from agent",
                        findings=[],
                        summary=content[:500],
                        metadata={"tool_calls": tool_call_count}
                    )

            output_data = json.loads(json_str)

            # Convert to Finding objects
            findings = []
            for f in output_data.get("findings", []):
                findings.append(Finding(
                    finding_id=f.get("finding_id", f"finding_{len(findings)}"),
                    agent_id=agent_input.agent_id,
                    domain=agent_input.domain,
                    severity=f.get("severity", "info"),
                    title=f.get("title", "Untitled finding"),
                    description=f.get("description", ""),
                    affected_systems=f.get("affected_systems", []),
                    evidence=f.get("evidence", {}),
                    confidence=float(f.get("confidence", 0.5)),
                    recommendations=f.get("recommendations", [])
                ))

            return MicroAgentOutput(
                agent_id=agent_input.agent_id,
                agent_type=agent_input.agent_type,
                domain=agent_input.domain,
                status="success",
                findings=findings,
                summary=output_data.get("summary", "Analysis complete"),
                metadata={"tool_calls": tool_call_count}
            )

        except Exception as e:
            import traceback
            return MicroAgentOutput(
                agent_id=agent_input.agent_id,
                agent_type=agent_input.agent_type,
                domain=agent_input.domain,
                status="failed",
                error_message=f"{str(e)}\n{traceback.format_exc()}",
                findings=[],
                summary=f"Agent execution failed: {str(e)}"
            )

    def create_supervisor(
        self,
        supervisor_input: SupervisorInput
    ) -> SupervisorOutput:
        """
        Create and execute a domain supervisor.

        Args:
            supervisor_input: Input with micro-agent outputs to aggregate

        Returns:
            SupervisorOutput with aggregated findings and domain summary
        """
        # Check if we have a registered implementation
        if supervisor_input.domain in self.supervisor_registry:
            supervisor_func = self.supervisor_registry[supervisor_input.domain]
            return supervisor_func(supervisor_input)

        # Otherwise, use generic supervisor
        return self._create_generic_supervisor(supervisor_input)

    def _create_generic_supervisor(
        self,
        supervisor_input: SupervisorInput
    ) -> SupervisorOutput:
        """
        Create a generic supervisor that aggregates micro-agent findings.
        """
        # Get versioned supervisor prompt
        prompt_name = f"{supervisor_input.domain}_supervisor"
        system_prompt = get_agent_prompt(prompt_name)

        # Create LLM
        llm = self.create_supervisor_llm()

        # Aggregate all findings by severity
        all_findings = []
        agent_summaries = []

        for output in supervisor_input.micro_agent_outputs:
            all_findings.extend(output.findings)
            agent_summaries.append(f"**{output.agent_type}** ({output.status}): {output.summary}")

        critical = [f for f in all_findings if f.severity == "critical"]
        high = [f for f in all_findings if f.severity == "high"]
        medium = [f for f in all_findings if f.severity == "medium"]
        low = [f for f in all_findings if f.severity == "low"]

        # Create analysis prompt
        user_message = f"""Review the findings from {len(supervisor_input.micro_agent_outputs)} micro-agents in the {supervisor_input.domain} domain.

**Agent Summaries:**
{chr(10).join(agent_summaries)}

**Findings Breakdown:**
- Critical: {len(critical)} findings
- High: {len(high)} findings
- Medium: {len(medium)} findings
- Low: {len(low)} findings

**Critical Findings:**
{self._format_findings_detailed(critical) if critical else 'None'}

**High Priority Findings:**
{self._format_findings_detailed(high) if high else 'None'}

Provide your analysis with:
1. **Executive Summary** (2-3 sentences): Overall domain security posture
2. **Cross-Agent Correlations**: Patterns confirmed by multiple agents
3. **Domain Health Score** (0-100): Overall health (100 = perfect)
4. **Key Recommendations**: Prioritized action items

Format as plain text with clear sections.
"""

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]

            result = llm.invoke(messages)

            # Parse health score from response
            health_score = self._extract_health_score(result.content, len(critical), len(high))

            # Extract correlations
            correlations = self._extract_correlations(result.content)

            return SupervisorOutput(
                supervisor_id=supervisor_input.supervisor_id,
                domain=supervisor_input.domain,
                micro_agent_count=len(supervisor_input.micro_agent_outputs),
                critical_findings=critical,
                high_findings=high,
                medium_findings=medium,
                low_findings=low,
                domain_summary=result.content,
                cross_agent_correlations=correlations,
                domain_health_score=health_score
            )

        except Exception as e:
            # Fallback to simple aggregation
            health_score = max(0, 100 - (len(critical) * 20) - (len(high) * 10) - (len(medium) * 5))

            return SupervisorOutput(
                supervisor_id=supervisor_input.supervisor_id,
                domain=supervisor_input.domain,
                micro_agent_count=len(supervisor_input.micro_agent_outputs),
                critical_findings=critical,
                high_findings=high,
                medium_findings=medium,
                low_findings=low,
                domain_summary=f"Aggregated {len(all_findings)} findings from {len(supervisor_input.micro_agent_outputs)} agents. Error during analysis: {str(e)}",
                cross_agent_correlations=[],
                domain_health_score=health_score
            )

    def _format_findings_detailed(self, findings: List[Finding]) -> str:
        """Format findings with details."""
        if not findings:
            return "None"

        result = []
        for f in findings[:10]:  # Max 10 findings
            result.append(f"- **{f.title}** (confidence: {f.confidence:.0%})")
            result.append(f"  {f.description[:200]}")
            if f.affected_systems:
                result.append(f"  Affected: {', '.join(f.affected_systems[:5])}")

        return "\n".join(result)

    def _extract_health_score(self, summary: str, critical_count: int, high_count: int) -> float:
        """Extract health score from supervisor summary or calculate default."""
        import re

        # Try to find health score in text
        patterns = [
            r'health score[:\s]+(\d+)',
            r'score[:\s]+(\d+)/100',
            r'(\d+)/100'
        ]

        for pattern in patterns:
            match = re.search(pattern, summary.lower())
            if match:
                score = float(match.group(1))
                if 0 <= score <= 100:
                    return score

        # Fallback calculation
        return max(0, 100 - (critical_count * 20) - (high_count * 10))

    def _extract_correlations(self, summary: str) -> List[str]:
        """Extract correlation patterns from supervisor summary."""
        correlations = []
        lines = summary.split('\n')

        # Look for correlation section
        in_correlation_section = False
        for line in lines:
            lower = line.lower()

            if 'correlation' in lower or 'patterns' in lower:
                in_correlation_section = True
                continue

            if in_correlation_section:
                # Stop at next section header
                if line.startswith('#') or line.startswith('**'):
                    if 'correlation' not in lower and 'pattern' not in lower:
                        break

                # Extract bullet points
                if line.strip().startswith('-') or line.strip().startswith('*'):
                    correlations.append(line.strip('- *').strip())

        return correlations[:5]  # Max 5 correlations


# Global factory instance
_factory: AgentFactory | None = None


def get_agent_factory() -> AgentFactory:
    """Get singleton agent factory."""
    global _factory
    if _factory is None:
        _factory = AgentFactory()
    return _factory
