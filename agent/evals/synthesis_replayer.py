"""
Synthesis replayer — task function factory for Langfuse run_experiment().

Replays the synthesis LLM call using stored trace inputs against a
configured model + prompt version. No live tools — pure LLM call.
"""

import logging
import time
from typing import Union

import litellm

from agent.evals.config import ExperimentConfig
from agent.langfuse_integration import get_prompt_manager
from agent.model_config import get_model_config

logger = logging.getLogger(__name__)

_RETRIES = 3
_INITIAL_DELAY = 5.0


def _completion_with_retry(*, model, messages, temperature, api_base, api_key) -> str:
    """LiteLLM completion with retry on transient errors (matches agent.llm.chat pattern)."""
    delay = _INITIAL_DELAY
    for attempt in range(_RETRIES):
        try:
            response = litellm.completion(
                model=model,
                messages=messages,
                temperature=temperature,
                api_base=api_base,
                api_key=api_key,
            )
            return response.choices[0].message.content or ""
        except (litellm.InternalServerError, litellm.RateLimitError) as e:
            if attempt < _RETRIES - 1:
                logger.warning(
                    "LLM %s on attempt %d/%d — retrying in %.0fs",
                    type(e).__name__, attempt + 1, _RETRIES, delay,
                )
                time.sleep(delay)
                delay *= 2
            else:
                raise
    return ""  # unreachable, satisfies type checker


def make_synthesis_task_fn(config: ExperimentConfig):
    """Create a task function for run_experiment() that replays synthesis.

    The returned callable conforms to Langfuse TaskFunction protocol:
        def task(*, item, **kwargs) -> str

    Args:
        config: Experiment configuration (model, prompt version, temperature)

    Returns:
        Callable that takes a dataset item and returns the synthesis output.
    """
    model_config = get_model_config()

    def task_fn(
        *,
        item: Union[dict, object],
        **kwargs,
    ) -> str:
        # Handle both dict items (LocalExperimentItem) and DatasetItem objects
        if isinstance(item, dict):
            inp = item.get("input", {})
        else:
            inp = item.input if hasattr(item, "input") else {}

        if isinstance(inp, str):
            import json
            try:
                inp = json.loads(inp)
            except (json.JSONDecodeError, TypeError):
                inp = {}

        # Determine system prompt — use stored production prompt or override version
        if config["synthesis_prompt_version"] is not None:
            pm = get_prompt_manager()
            system_content = pm.get_prompt(
                "first-light-synthesis",
                version=config["synthesis_prompt_version"],
            )
        else:
            system_content = inp.get("synthesis_system_prompt", "")

        user_content = inp.get("synthesis_user_message", "")

        if not system_content or not user_content:
            logger.error(
                "Empty system (%d chars) or user (%d chars) in replay — skipping",
                len(system_content), len(user_content),
            )
            return "[ERROR: empty input for synthesis replay]"

        messages = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content},
        ]

        return _completion_with_retry(
            model=config["model"],
            messages=messages,
            temperature=config["temperature"],
            api_base=model_config.litellm_base_url,
            api_key=model_config.litellm_api_key,
        )

    return task_fn
