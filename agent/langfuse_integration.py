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
def get_langfuse_client() -> Langfuse:
    """Get singleton Langfuse client.

    Raises:
        ValueError: If required Langfuse environment variables are not set
    """
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    host = os.getenv("LANGFUSE_HOST")

    if not secret_key or not public_key or not host:
        missing = []
        if not secret_key:
            missing.append("LANGFUSE_SECRET_KEY")
        if not public_key:
            missing.append("LANGFUSE_PUBLIC_KEY")
        if not host:
            missing.append("LANGFUSE_HOST")

        raise ValueError(
            f"CONFIGURATION ERROR: Missing required Langfuse environment variables: {', '.join(missing)}\n"
            f"Set these in your .env file. NO FALLBACKS - configuration must be explicit."
        )

    return Langfuse(
        secret_key=secret_key,
        public_key=public_key,
        host=host
    )


class PromptManager:
    """Manages versioned prompts from Langfuse."""

    def __init__(self):
        self.client = get_langfuse_client()
        self._cache: Dict[str, str] = {}

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
            Prompt text from Langfuse

        Raises:
            ValueError: If prompt not found in Langfuse - NO FALLBACKS
        """
        cache_key = f"{prompt_name}:v{version}" if version else f"{prompt_name}:latest"

        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

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
            raise ValueError(
                f"PROMPT NOT FOUND: Could not fetch prompt '{prompt_name}' from Langfuse.\n"
                f"Error: {e}\n"
                f"NO FALLBACKS - prompts must exist in Langfuse with label 'production'.\n"
                f"Create this prompt in Langfuse before using it."
            )

    def create_prompt(
        self,
        name: str,
        prompt: str,
        labels: Optional[list] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Create or update a prompt in Langfuse.

        Args:
            name: Prompt name (unique identifier)
            prompt: Prompt text/template
            labels: Labels to apply (e.g., ["production", "v1"])
            config: Additional config (model settings, etc.)

        Raises:
            Exception: If prompt creation fails - NO FALLBACKS
        """
        self.client.create_prompt(
            name=name,
            prompt=prompt,
            labels=labels or [],
            config=config or {}
        )
        print(f"✓ Created/updated prompt '{name}' in Langfuse")


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


def init_langfuse() -> None:
    """
    Initialize Langfuse integration.

    Raises:
        ValueError: If Langfuse configuration is missing or auth fails - NO FALLBACKS
    """
    client = get_langfuse_client()

    # Test connection - fail loudly if it doesn't work
    try:
        client.auth_check()
        print("✓ Langfuse integration initialized successfully")
    except Exception as e:
        raise ValueError(
            f"LANGFUSE AUTH FAILED: Could not authenticate with Langfuse.\n"
            f"Error: {e}\n"
            f"NO FALLBACKS - fix your Langfuse configuration in .env"
        )
