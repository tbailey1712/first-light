"""
Central LLM harness for First Light.

All LLM calls go through here. LiteLLM routes to the configured model.
Langfuse tracing is done via the Langfuse SDK directly — no LiteLLM callback
integration needed (avoids version skew issues).

Public API:
    chat(messages, agent_type, ...)          -> litellm.ModelResponse
    run_react_loop(system, user, tools, ...) -> str
"""

import json
import logging
from typing import Literal, Optional

import litellm
from langchain_core.tools import BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from langfuse import get_client as get_langfuse_client

from agent.model_config import (
    get_model_config,
    get_model_for_agent_type,
    get_temperature_for_agent_type,
)

logger = logging.getLogger(__name__)

AgentType = Literal["micro", "supervisor", "synthesis", "weekly", "monthly"]

MAX_TOOL_ITERATIONS = 12

# Silence LiteLLM's verbose logging
litellm.suppress_debug_info = True


# ── Core call ──────────────────────────────────────────────────────────────────

def chat(
    messages: list[dict],
    agent_type: AgentType,
    tools: Optional[list[dict]] = None,
    session_id: Optional[str] = None,
    agent_name: Optional[str] = None,
) -> litellm.ModelResponse:
    """
    Single LLM call through LiteLLM with Langfuse generation tracing.

    Creates a Langfuse generation span capturing model, input, output, and
    token usage. Nested inside the caller's active span when one exists.

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

    with lf.start_as_current_generation(
        name=agent_name or agent_type,
        model=model,
        input=messages,
        model_parameters={"temperature": temperature},
    ):
        if session_id:
            lf.update_current_trace(session_id=session_id)

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

        response = litellm.completion(**kwargs)

        msg = response.choices[0].message
        lf.update_current_generation(
            output=msg.content if not msg.tool_calls else [
                {"name": tc.function.name, "arguments": tc.function.arguments}
                for tc in msg.tool_calls
            ],
            usage_details={
                "input": response.usage.prompt_tokens if response.usage else 0,
                "output": response.usage.completion_tokens if response.usage else 0,
                "total": response.usage.total_tokens if response.usage else 0,
            },
        )

    return response


# ── ReAct loop ─────────────────────────────────────────────────────────────────

def run_react_loop(
    system_prompt: str,
    user_prompt: str,
    tools: list[BaseTool],
    agent_name: str,
    agent_type: AgentType = "micro",
    session_id: Optional[str] = None,
) -> str:
    """
    ReAct tool-calling loop via LiteLLM.

    Each iteration is traced as a child generation under an agent span.

    Args:
        system_prompt: Domain-specific system prompt
        user_prompt:   Analysis request
        tools:         LangChain @tool decorated callables
        agent_name:    Name used in Langfuse traces and logs
        agent_type:    Model tier (default: "micro")
        session_id:    Groups all calls in a report run under one Langfuse session
    """
    lf = get_langfuse_client()
    tool_schemas = [convert_to_openai_tool(t) for t in tools]
    tool_map = {t.name: t for t in tools}

    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    with lf.start_as_current_span(name=agent_name, input=user_prompt):
        if session_id:
            lf.update_current_trace(session_id=session_id)

        for _ in range(MAX_TOOL_ITERATIONS):
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

            # Append assistant turn with tool calls
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

            # Execute each tool call
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

                messages.append({
                    "role": "tool",
                    "content": str(result),
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
