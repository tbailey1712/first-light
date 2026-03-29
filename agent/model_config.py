"""
Model configuration for First Light agents.

Defaults to MAXIMUM INTELLIGENCE - best available models.
Configurable via environment variables if needed.
"""

from typing import Literal
from pydantic import BaseModel, Field
import os


ModelName = Literal[
    # Anthropic Claude (via LiteLLM router)
    "claude-opus-4-6",
    "claude-opus-4-5",
    "claude-sonnet-4-6",
    "claude-sonnet-4-5",
    "claude-haiku-4-5",

    # OpenAI GPT family (via LiteLLM router)
    "gpt-4o",
    "gpt-4o-mini",

    # Google Gemini (via LiteLLM router)
    "gemini/gemini-2.0-flash",
    "gemini/gemini-1.5-pro",

    # X.ai Grok (via LiteLLM router)
    "openrouter/x-ai/grok-3",
]


class ModelConfig(BaseModel):
    """Model selection for different agent types.

    DEFAULTS TO MAX INTELLIGENCE - Best available models.
    Override via environment variables if you want different models.
    """

    # LiteLLM Router Configuration - REQUIRED
    litellm_base_url: str = Field(
        default=...,  # REQUIRED - no default
        description="LiteLLM router base URL (REQUIRED)"
    )

    litellm_api_key: str = Field(
        default=...,  # REQUIRED - no default
        description="LiteLLM API key (REQUIRED)"
    )

    # Micro-agents: Individual specialized analysis - REQUIRED
    micro_agent_model: ModelName = Field(
        default=...,  # REQUIRED - no default
        description="Model for micro-agents (REQUIRED)"
    )

    # Domain supervisors: Aggregate findings from micro-agents - REQUIRED
    supervisor_model: ModelName = Field(
        default=...,  # REQUIRED - no default
        description="Model for domain supervisors (REQUIRED)"
    )

    # Synthesis: Top-level cross-domain analysis - REQUIRED
    synthesis_model: ModelName = Field(
        default=...,  # REQUIRED - no default
        description="Model for synthesis agent (REQUIRED)"
    )

    # Temporal aggregation: Weekly/monthly reports - REQUIRED
    weekly_model: ModelName = Field(
        default=...,  # REQUIRED - no default
        description="Model for weekly aggregation (REQUIRED)"
    )

    monthly_model: ModelName = Field(
        default=...,  # REQUIRED - no default
        description="Model for monthly aggregation (REQUIRED)"
    )

    # Temperature settings - REQUIRED
    micro_agent_temperature: float = Field(
        default=...,  # REQUIRED - no default
        ge=0.0,
        le=2.0,
        description="Temperature for micro-agents (REQUIRED)"
    )

    supervisor_temperature: float = Field(
        default=...,  # REQUIRED - no default
        ge=0.0,
        le=2.0,
        description="Temperature for supervisors (REQUIRED)"
    )

    synthesis_temperature: float = Field(
        default=...,  # REQUIRED - no default
        ge=0.0,
        le=2.0,
        description="Temperature for synthesis (REQUIRED)"
    )


# Global config instance
_config: ModelConfig | None = None


def get_model_config() -> ModelConfig:
    """Get the model configuration singleton.

    Raises:
        ValueError: If required environment variables are not set
    """
    global _config
    if _config is None:
        # Check required environment variables
        required_vars = {
            "LITELLM_BASE_URL": os.getenv("LITELLM_BASE_URL"),
            "LITELLM_API_KEY": os.getenv("LITELLM_API_KEY"),
            "MICRO_AGENT_MODEL": os.getenv("MICRO_AGENT_MODEL"),
            "SUPERVISOR_MODEL": os.getenv("SUPERVISOR_MODEL"),
            "SYNTHESIS_MODEL": os.getenv("SYNTHESIS_MODEL"),
            "WEEKLY_MODEL": os.getenv("WEEKLY_MODEL"),
            "MONTHLY_MODEL": os.getenv("MONTHLY_MODEL"),
            "MICRO_AGENT_TEMPERATURE": os.getenv("MICRO_AGENT_TEMPERATURE"),
            "SUPERVISOR_TEMPERATURE": os.getenv("SUPERVISOR_TEMPERATURE"),
            "SYNTHESIS_TEMPERATURE": os.getenv("SYNTHESIS_TEMPERATURE"),
        }

        missing = [k for k, v in required_vars.items() if not v]
        if missing:
            raise ValueError(
                f"CONFIGURATION ERROR: Missing required environment variables: {', '.join(missing)}\n"
                f"Set these in your .env file. No defaults provided - configuration must be explicit."
            )

        _config = ModelConfig(
            litellm_base_url=required_vars["LITELLM_BASE_URL"],
            litellm_api_key=required_vars["LITELLM_API_KEY"],
            micro_agent_model=required_vars["MICRO_AGENT_MODEL"],
            supervisor_model=required_vars["SUPERVISOR_MODEL"],
            synthesis_model=required_vars["SYNTHESIS_MODEL"],
            weekly_model=required_vars["WEEKLY_MODEL"],
            monthly_model=required_vars["MONTHLY_MODEL"],
            micro_agent_temperature=float(required_vars["MICRO_AGENT_TEMPERATURE"]),
            supervisor_temperature=float(required_vars["SUPERVISOR_TEMPERATURE"]),
            synthesis_temperature=float(required_vars["SYNTHESIS_TEMPERATURE"]),
        )
    return _config


def get_model_for_agent_type(agent_type: Literal["micro", "supervisor", "synthesis", "weekly", "monthly"]) -> str:
    """Get the configured model for a specific agent type."""
    config = get_model_config()

    model_map = {
        "micro": config.micro_agent_model,
        "supervisor": config.supervisor_model,
        "synthesis": config.synthesis_model,
        "weekly": config.weekly_model,
        "monthly": config.monthly_model,
    }

    return model_map[agent_type]


def get_temperature_for_agent_type(agent_type: Literal["micro", "supervisor", "synthesis"]) -> float:
    """Get the configured temperature for a specific agent type."""
    config = get_model_config()

    temp_map = {
        "micro": config.micro_agent_temperature,
        "supervisor": config.supervisor_temperature,
        "synthesis": config.synthesis_temperature,
    }

    return temp_map[agent_type]


# Convenience functions for creating LLMs
def create_llm_for_agent_type(
    agent_type: Literal["micro", "supervisor", "synthesis", "weekly", "monthly"],
    **kwargs
):
    """Create an LLM instance configured for the specified agent type.

    Args:
        agent_type: Type of agent (micro, supervisor, synthesis, etc.)
        **kwargs: Additional arguments to pass to ChatOpenAI (via LiteLLM)

    Returns:
        Configured LLM instance (via LiteLLM router)
    """
    from langchain_openai import ChatOpenAI

    config = get_model_config()
    model = get_model_for_agent_type(agent_type)

    # Determine temperature (use default if not micro/supervisor/synthesis)
    if agent_type in ["micro", "supervisor", "synthesis"]:
        temperature = kwargs.pop("temperature", get_temperature_for_agent_type(agent_type))
    else:
        temperature = kwargs.pop("temperature", 0.1)

    # Use LiteLLM router via OpenAI-compatible interface
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        base_url=config.litellm_base_url,
        api_key=config.litellm_api_key,
        **kwargs
    )


def print_model_config():
    """Print current model configuration for debugging."""
    config = get_model_config()

    print("=" * 80)
    print("FIRST LIGHT - MODEL CONFIGURATION")
    print("=" * 80)
    print()
    print("🧠 MICRO-AGENTS (Specialized Analysis)")
    print(f"   Model: {config.micro_agent_model}")
    print(f"   Temperature: {config.micro_agent_temperature}")
    print()
    print("🎯 DOMAIN SUPERVISORS (Aggregation)")
    print(f"   Model: {config.supervisor_model}")
    print(f"   Temperature: {config.supervisor_temperature}")
    print()
    print("📊 SYNTHESIS AGENT (Final Report)")
    print(f"   Model: {config.synthesis_model}")
    print(f"   Temperature: {config.synthesis_temperature}")
    print()
    print("📅 TEMPORAL AGGREGATION")
    print(f"   Weekly:  {config.weekly_model}")
    print(f"   Monthly: {config.monthly_model}")
    print()
    print("💡 To override, set environment variables:")
    print("   MICRO_AGENT_MODEL=claude-opus-4-6")
    print("   SUPERVISOR_MODEL=claude-opus-4-6")
    print("   SYNTHESIS_MODEL=claude-opus-4-6")
    print("=" * 80)


if __name__ == "__main__":
    print_model_config()
