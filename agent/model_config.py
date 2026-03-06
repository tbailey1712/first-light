"""
Model configuration for First Light agents.

Defaults to MAXIMUM INTELLIGENCE - best available models.
Configurable via environment variables if needed.
"""

from typing import Literal
from pydantic import BaseModel, Field
import os


ModelName = Literal[
    # Anthropic Claude (recommended)
    "claude-opus-4-6",
    "claude-sonnet-4-5-20250929",
    "claude-haiku-4-5-20251001",

    # OpenAI GPT-4 family
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",

    # OpenAI o1/o3 family (reasoning models)
    "o1",
    "o1-mini",
    "o3-mini",
]


class ModelConfig(BaseModel):
    """Model selection for different agent types.

    DEFAULTS TO MAX INTELLIGENCE - Best available models.
    Override via environment variables if you want different models.
    """

    # Micro-agents: Individual specialized analysis
    micro_agent_model: ModelName = Field(
        default=os.getenv("MICRO_AGENT_MODEL", "claude-sonnet-4-5-20250929"),
        description="Model for micro-agents (individual specialized analysts)"
    )

    # Domain supervisors: Aggregate findings from micro-agents
    supervisor_model: ModelName = Field(
        default=os.getenv("SUPERVISOR_MODEL", "claude-opus-4-6"),
        description="Model for domain supervisors (aggregate multiple agents)"
    )

    # Synthesis: Top-level cross-domain analysis
    synthesis_model: ModelName = Field(
        default=os.getenv("SYNTHESIS_MODEL", "claude-opus-4-6"),
        description="Model for synthesis agent (final report generation)"
    )

    # Temporal aggregation: Weekly/monthly reports
    weekly_model: ModelName = Field(
        default=os.getenv("WEEKLY_MODEL", "claude-opus-4-6"),
        description="Model for weekly aggregation"
    )

    monthly_model: ModelName = Field(
        default=os.getenv("MONTHLY_MODEL", "claude-opus-4-6"),
        description="Model for monthly aggregation"
    )

    # Temperature settings
    micro_agent_temperature: float = Field(
        default=float(os.getenv("MICRO_AGENT_TEMPERATURE", "0.0")),
        ge=0.0,
        le=2.0,
        description="Temperature for micro-agents (0.0 = deterministic)"
    )

    supervisor_temperature: float = Field(
        default=float(os.getenv("SUPERVISOR_TEMPERATURE", "0.1")),
        ge=0.0,
        le=2.0,
        description="Temperature for supervisors"
    )

    synthesis_temperature: float = Field(
        default=float(os.getenv("SYNTHESIS_TEMPERATURE", "0.2")),
        ge=0.0,
        le=2.0,
        description="Temperature for synthesis (slightly higher for better writing)"
    )


# Global config instance
_config: ModelConfig | None = None


def get_model_config() -> ModelConfig:
    """Get the model configuration singleton."""
    global _config
    if _config is None:
        _config = ModelConfig()
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
        **kwargs: Additional arguments to pass to ChatAnthropic/ChatOpenAI

    Returns:
        Configured LLM instance
    """
    from langchain_anthropic import ChatAnthropic
    from langchain_openai import ChatOpenAI

    model = get_model_for_agent_type(agent_type)

    # Determine temperature (use default if not micro/supervisor/synthesis)
    if agent_type in ["micro", "supervisor", "synthesis"]:
        temperature = kwargs.pop("temperature", get_temperature_for_agent_type(agent_type))
    else:
        temperature = kwargs.pop("temperature", 0.1)

    # Use appropriate LLM class based on model
    if model.startswith("claude"):
        return ChatAnthropic(
            model=model,
            temperature=temperature,
            **kwargs
        )
    elif model.startswith("gpt") or model.startswith("o1") or model.startswith("o3"):
        return ChatOpenAI(
            model=model,
            temperature=temperature,
            **kwargs
        )
    else:
        raise ValueError(f"Unknown model: {model}")


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
