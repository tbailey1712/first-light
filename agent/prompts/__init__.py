"""
First Light Agent Prompts

Prompt templates for the AI agent.
"""

from agent.prompts.system import (
    get_system_prompt,
    NETWORK_KNOWLEDGE,
    DAILY_REPORT_SYSTEM_PROMPT,
)

__all__ = [
    "get_system_prompt",
    "NETWORK_KNOWLEDGE",
    "DAILY_REPORT_SYSTEM_PROMPT",
]
