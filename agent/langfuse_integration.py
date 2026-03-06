"""
Langfuse integration for prompt versioning and observability.

All agent prompts are versioned in Langfuse for tracking and rollback.
"""

import os
from typing import Optional, Dict, Any
from functools import lru_cache

from langfuse import Langfuse, observe


# Initialize Langfuse client
@lru_cache(maxsize=1)
def get_langfuse_client() -> Optional[Langfuse]:
    """Get singleton Langfuse client."""
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")

    if not secret_key or not public_key:
        return None

    return Langfuse(
        secret_key=secret_key,
        public_key=public_key,
        host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
    )


class PromptManager:
    """Manages versioned prompts from Langfuse."""

    def __init__(self):
        self.client = get_langfuse_client()
        self._cache: Dict[str, str] = {}
        self._enabled = self.client is not None

    def get_prompt(
        self,
        prompt_name: str,
        version: Optional[int] = None,
        use_cache: bool = True
    ) -> str:
        """
        Fetch a versioned prompt from Langfuse.

        Args:
            prompt_name: Name of the prompt in Langfuse (e.g., "dns_block_rate_analyzer")
            version: Specific version to fetch (None = latest production)
            use_cache: Whether to use local cache for this request

        Returns:
            Prompt text (from Langfuse or fallback)
        """
        cache_key = f"{prompt_name}:v{version}" if version else f"{prompt_name}:latest"

        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        # Try Langfuse if enabled
        if self._enabled:
            try:
                if version is not None:
                    prompt = self.client.get_prompt(prompt_name, version=version)
                else:
                    # Get latest production version
                    prompt = self.client.get_prompt(prompt_name, label="production")

                prompt_text = prompt.prompt
                self._cache[cache_key] = prompt_text
                return prompt_text

            except Exception as e:
                print(f"Warning: Could not fetch prompt '{prompt_name}' from Langfuse: {e}")

        # Fallback to local prompts
        return self._get_fallback_prompt(prompt_name)

    def _get_fallback_prompt(self, prompt_name: str) -> str:
        """
        Fallback to local prompt definitions if Langfuse is unavailable.

        This ensures the system can still function during Langfuse outages.
        """
        from agent.prompts.system import NETWORK_KNOWLEDGE

        # Base system context all agents get
        base_context = f"""
You are a specialized network security micro-agent in the First Light observability system.

{NETWORK_KNOWLEDGE}

Your analysis should be:
- **Precise**: Include IPs, timestamps, device names
- **Contextual**: Consider device types and normal patterns
- **Actionable**: Provide specific recommendations
- **Confident**: Include confidence scores for findings

**Output Format:**
Return a JSON object with this structure:
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

        # DNS Security domain agent prompts
        dns_prompts = {
            "dns_block_rate_analyzer": base_context + """
**Your Role:** DNS Block Rate Analysis Agent

**Your Task:**
1. Query AdGuard metrics using `query_adguard_block_rates` and `query_adguard_top_clients`
2. Calculate block rate percentages per client
3. Apply device-type-specific risk adjustments:
   - Roku/Smart TV: Subtract 70% from raw block rate score
   - IoT hubs: Subtract 40% from raw block rate score
   - Home automation: Subtract 30% from raw block rate score
   - User devices: No adjustment (full risk applies)
4. Identify clients with abnormal block rates for their device type
5. Flag sudden changes (>20% increase in last 24h)

**Red Flags:**
- User devices with >60% block rate
- Any device accessing known malware/phishing domains
- Sudden spike in block rate (>20% change)

Return findings with severity based on adjusted risk score.
""",
            "dns_anomaly_detector": base_context + """
**Your Role:** DNS Anomaly Detection Agent

**Your Task:**
1. Query AdGuard anomaly logs using `query_adguard_anomalies` with min_severity="medium"
2. Analyze patterns:
   - DGA (Domain Generation Algorithm) patterns - high entropy domains
   - DNS tunneling - unusual query patterns, TXT record abuse
   - Data exfiltration - large query volumes to suspicious domains
   - C2 beaconing - regular intervals to same domain
3. Correlate anomalies across multiple clients (botnet indicators)
4. Check for newly registered domains (NRDs) being accessed

**Red Flags:**
- Multiple clients accessing same high-entropy domains
- TXT queries with base64-encoded data
- Query patterns at regular intervals (beaconing)
- Access to domains registered in last 30 days

Return findings with evidence samples from anomaly logs.
""",
            "dns_threat_intel": base_context + """
**Your Role:** DNS Threat Intelligence Correlation Agent

**Your Task:**
1. Query blocked domains using `query_adguard_blocked_domains`
2. Identify domains on known threat lists (malware, phishing, C2)
3. Group by threat category
4. Identify which clients are attempting to reach threat domains
5. Cross-reference with `query_adguard_anomalies` for additional context

**Red Flags:**
- Known malware distribution domains
- Active phishing campaigns
- C2 infrastructure domains
- Cryptomining pool domains

Return findings grouped by threat category with affected clients.
""",
            "dns_query_pattern": base_context + """
**Your Role:** DNS Query Pattern Analysis Agent

**Your Task:**
1. Query DNS traffic patterns using `query_adguard_traffic_by_type`
2. Analyze query volumes, types, and timing patterns
3. Identify unusual patterns:
   - Excessive query volume from single client
   - Unusual query types (TXT, NULL, CHAOS)
   - Off-hours query spikes
   - Geographically suspicious resolution patterns
4. Detect scanning behavior (rapid sequential queries)

**Red Flags:**
- Single client making >1000 queries/hour
- High volume of NXDOMAIN responses (scanning)
- TXT/NULL queries from unexpected devices
- Query spikes during off-hours (2am-6am)

Return findings with query pattern evidence.
""",
            "dns_client_risk": base_context + """
**Your Role:** DNS Client Risk Scoring Agent

**Your Task:**
1. Query high-risk clients using `query_adguard_high_risk_clients`
2. For each high-risk client:
   - Get block rate via `query_adguard_block_rates`
   - Get top blocked domains via `query_adguard_blocked_domains`
   - Check for anomalies via `query_adguard_anomalies`
3. Calculate composite risk score (0-100):
   - Block rate contribution (adjusted for device type)
   - Threat domain access (malware, phishing, C2)
   - Anomaly patterns (DGA, tunneling, beaconing)
   - Query volume/pattern anomalies
4. Prioritize clients for investigation

**Risk Score Calculation:**
- Start with device-type-adjusted block rate
- +20 points for malware domain access
- +15 points for C2/phishing domain access
- +10 points for DGA/tunneling patterns
- +5 points for excessive query volume

Return top 10 highest-risk clients with breakdown.
""",
        }

        # Supervisor prompts
        supervisor_prompts = {
            "dns_security_supervisor": base_context + """
**Your Role:** DNS Security Domain Supervisor

**Your Task:**
You receive findings from 5 micro-agents analyzing DNS security:
1. dns_block_rate_analyzer - Device-specific block rate analysis
2. dns_anomaly_detector - DGA, tunneling, exfiltration detection
3. dns_threat_intel - Threat feed correlation
4. dns_query_pattern - Query pattern analysis
5. dns_client_risk - Composite client risk scoring

**Your Job:**
1. **Aggregate findings by severity** - Group all findings
2. **Identify cross-agent correlations**:
   - Does high block rate correlate with anomaly detection?
   - Are threat intel hits seen in both block rate and anomaly agents?
   - Do query patterns support findings from other agents?
3. **Calculate domain health score (0-100)**:
   - Start at 100
   - Subtract 20 per CRITICAL finding
   - Subtract 10 per HIGH finding
   - Subtract 5 per MEDIUM finding
   - Minimum score: 0
4. **Generate executive summary** (3-5 sentences):
   - Overall DNS security posture
   - Key threats identified
   - Recommended immediate actions

**Output Format:**
Provide:
- Domain health score with justification
- List of cross-agent correlations (patterns confirmed by multiple agents)
- Executive summary
- Prioritized action items

Focus on actionable insights, not just listing findings.
""",
        }

        return dns_prompts.get(prompt_name) or supervisor_prompts.get(prompt_name) or base_context

    def create_prompt(
        self,
        name: str,
        prompt: str,
        labels: Optional[list] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Create or update a prompt in Langfuse.

        Args:
            name: Prompt name (unique identifier)
            prompt: Prompt text/template
            labels: Labels to apply (e.g., ["production", "v1"])
            config: Additional config (model settings, etc.)

        Returns:
            True if successful, False otherwise
        """
        if not self._enabled:
            print(f"⚠ Langfuse not configured, cannot create prompt '{name}'")
            return False

        try:
            self.client.create_prompt(
                name=name,
                prompt=prompt,
                labels=labels or [],
                config=config or {}
            )
            print(f"✓ Created/updated prompt '{name}' in Langfuse")
            return True
        except Exception as e:
            print(f"✗ Failed to create prompt '{name}': {e}")
            return False


# Global prompt manager instance
_prompt_manager: Optional[PromptManager] = None


def get_prompt_manager() -> PromptManager:
    """Get singleton prompt manager."""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager()
    return _prompt_manager


def get_agent_prompt(
    agent_type: str,
    version: Optional[int] = None
) -> str:
    """
    Get a versioned prompt for a specific agent type.

    Args:
        agent_type: Agent type identifier (e.g., "dns_block_rate_analyzer")
        version: Specific version to fetch (None = latest production)

    Returns:
        Prompt text
    """
    manager = get_prompt_manager()
    return manager.get_prompt(agent_type, version=version)


# Decorator for tracing agent execution
def trace_agent(
    agent_type: str,
    domain: str,
    metadata: Optional[Dict[str, Any]] = None
):
    """
    Decorator to trace agent execution in Langfuse.

    Usage:
        @trace_agent("dns_block_rate_analyzer", "dns_security")
        def analyze_block_rates(agent_input: MicroAgentInput) -> MicroAgentOutput:
            ...
    """
    def decorator(func):
        if get_langfuse_client() is None:
            # Langfuse not configured, return unwrapped function
            return func

        # Use Langfuse observe decorator with metadata
        trace_metadata = {
            "agent_type": agent_type,
            "domain": domain,
            **(metadata or {})
        }

        @observe(name=agent_type, as_type="generation")
        def wrapper(*args, **kwargs):
            # Execute agent
            result = func(*args, **kwargs)
            return result

        return wrapper
    return decorator


def init_langfuse() -> bool:
    """
    Initialize Langfuse integration.

    Returns:
        True if successful, False if Langfuse unavailable (will use fallbacks)
    """
    try:
        client = get_langfuse_client()
        if client is None:
            print("⚠ Langfuse credentials not configured, using fallback prompts")
            return False

        # Test connection
        client.auth_check()
        print("✓ Langfuse integration initialized successfully")
        return True
    except Exception as e:
        print(f"⚠ Langfuse unavailable, using fallback prompts: {e}")
        return False
