"""
Central LLM harness for First Light.

All LLM calls go through here. LiteLLM routes to the configured model.
Langfuse tracing uses the @observe decorator + SDK update methods (4.0 API).

Public API:
    chat(messages, agent_type, ...)          -> litellm.ModelResponse
    run_react_loop(system, user, tools, ...) -> str
"""

import json
import logging
import time
from typing import Literal, Optional

import litellm
from langchain_core.tools import BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from langfuse import observe, get_client as get_langfuse_client, LangfuseOtelSpanAttributes
from opentelemetry import trace as otel_trace

from agent.model_config import (
    get_model_config,
    get_model_for_agent_type,
    get_temperature_for_agent_type,
)

logger = logging.getLogger(__name__)

AgentType = Literal["micro", "supervisor", "synthesis", "weekly", "monthly"]

MAX_TOOL_ITERATIONS = 12

# Maximum characters per tool result before truncation.
# Keeps context window from exploding across multi-iteration ReAct loops.
# ~10k chars ≈ ~2500 tokens — enough for rich JSON, not enough to blow 200k context.
MAX_TOOL_RESULT_CHARS = 10_000

# Silence LiteLLM's verbose logging
litellm.suppress_debug_info = True


def _set_trace_session(session_id: Optional[str]) -> None:
    """Attach session_id to the current active OTel span (Langfuse trace attribute)."""
    if session_id:
        span = otel_trace.get_current_span()
        span.set_attribute(LangfuseOtelSpanAttributes.TRACE_SESSION_ID, session_id)


# ── Core call ──────────────────────────────────────────────────────────────────

@observe(as_type="generation", capture_input=False, capture_output=False)
def chat(
    messages: list[dict],
    agent_type: AgentType,
    tools: Optional[list[dict]] = None,
    session_id: Optional[str] = None,
    agent_name: Optional[str] = None,
) -> litellm.ModelResponse:
    """
    Single LLM call through LiteLLM with Langfuse generation tracing.

    Decorated with @observe(as_type="generation") — automatically nested
    inside the caller's active span when one exists.

    Args:
        messages:    OpenAI-format message list
        agent_type:  Selects model + temperature from model_config
        tools:       OpenAI-format tool schemas (enables tool_choice=auto)
        session_id:  Groups all calls in a report run under one Langfuse session
        agent_name:  Langfuse generation name for this call
    """
    config = get_model_config()
    model = get_model_for_agent_type(agent_type)
    temperature = (
        get_temperature_for_agent_type(agent_type)
        if agent_type in ("micro", "supervisor", "synthesis")
        else 0.1
    )

    lf = get_langfuse_client()
    _set_trace_session(session_id)
    lf.update_current_generation(
        name=agent_name or agent_type,
        model=model,
        input=messages,
        model_parameters={"temperature": temperature},
    )

    kwargs: dict = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "api_base": config.litellm_base_url,
        "api_key": config.litellm_api_key,
    }
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"

    # Log approximate context size to help diagnose future 500s
    _ctx_chars = sum(len(str(m.get("content", ""))) for m in messages)
    if _ctx_chars > 50_000:
        logger.warning(
            "%s: large context (%d chars ≈ %d tokens) before LLM call",
            agent_name or agent_type, _ctx_chars, _ctx_chars // 4,
        )

    # Retry on transient 500s (LiteLLM proxies Anthropic overload as InternalServerError)
    _retries = 3
    _delay = 5.0
    last_exc = None
    for attempt in range(_retries):
        try:
            response = litellm.completion(**kwargs)
            break
        except litellm.InternalServerError as e:
            last_exc = e
            if attempt < _retries - 1:
                logger.warning(
                    "LLM 500 on attempt %d/%d for %s — retrying in %.0fs",
                    attempt + 1, _retries, agent_name or agent_type, _delay,
                )
                time.sleep(_delay)
                _delay *= 2
            else:
                raise
        except litellm.RateLimitError as e:
            last_exc = e
            if attempt < _retries - 1:
                logger.warning(
                    "LLM rate limit on attempt %d/%d — retrying in %.0fs",
                    attempt + 1, _retries, _delay,
                )
                time.sleep(_delay)
                _delay *= 2
            else:
                raise

    msg = response.choices[0].message
    lf.update_current_generation(
        output=(
            msg.content if not msg.tool_calls
            else [{"name": tc.function.name, "arguments": tc.function.arguments}
                  for tc in msg.tool_calls]
        ),
        usage_details={
            "input": response.usage.prompt_tokens if response.usage else 0,
            "output": response.usage.completion_tokens if response.usage else 0,
            "total": response.usage.total_tokens if response.usage else 0,
        },
    )

    return response


# ── ReAct loop ─────────────────────────────────────────────────────────────────

@observe(as_type="span", capture_input=False, capture_output=False)
def run_react_loop(
    system_prompt: str,
    user_prompt: str,
    tools: list[BaseTool],
    agent_name: str,
    agent_type: AgentType = "micro",
    session_id: Optional[str] = None,
    max_iterations: int = MAX_TOOL_ITERATIONS,
) -> str:
    """
    ReAct tool-calling loop via LiteLLM.

    Each iteration's LLM call is traced as a child generation under this span.

    Args:
        system_prompt: Domain-specific system prompt
        user_prompt:   Analysis request
        tools:         LangChain @tool decorated callables
        agent_name:    Name used in Langfuse traces and logs
        agent_type:    Model tier (default: "micro")
        session_id:    Groups all calls in a report run under one Langfuse session
    """
    lf = get_langfuse_client()
    _set_trace_session(session_id)
    lf.update_current_span(name=agent_name, input=user_prompt)

    tool_schemas = [convert_to_openai_tool(t) for t in tools]
    tool_map = {t.name: t for t in tools}

    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    for _ in range(max_iterations):
        response = chat(
            messages,
            agent_type,
            tools=tool_schemas,
            session_id=session_id,
            agent_name=f"{agent_name}/llm",
        )
        msg = response.choices[0].message

        if not msg.tool_calls:
            result = msg.content or f"[{agent_name}: no content returned]"
            lf.update_current_span(output=result)
            return result

        # Append assistant turn
        messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ],
        })

        # Execute tool calls
        for tc in msg.tool_calls:
            tool = tool_map.get(tc.function.name)
            if tool:
                try:
                    args = json.loads(tc.function.arguments)
                    result = tool.invoke(args)
                except Exception as e:
                    result = f"Tool error: {e}"
            else:
                result = f"Unknown tool: {tc.function.name}"

            result_str = str(result)
            if len(result_str) > MAX_TOOL_RESULT_CHARS:
                result_str = (
                    result_str[:MAX_TOOL_RESULT_CHARS]
                    + f"\n... [truncated: {len(result_str) - MAX_TOOL_RESULT_CHARS} chars omitted to fit context window]"
                )
                logger.debug(
                    "%s: tool %s result truncated to %d chars",
                    agent_name, tc.function.name, MAX_TOOL_RESULT_CHARS,
                )

            messages.append({
                "role": "tool",
                "content": result_str,
                "tool_call_id": tc.id,
            })

    # Hit iteration limit — force a final answer
    messages.append({
        "role": "user",
        "content": "Provide your final summary now based on the data collected.",
    })
    response = chat(messages, agent_type, session_id=session_id, agent_name=f"{agent_name}/llm")
    result = response.choices[0].message.content or f"[{agent_name}: no final content]"
    lf.update_current_span(output=result)
    return result
