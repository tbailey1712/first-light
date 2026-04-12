"""
Extract SynthesisInput from Langfuse daily-report traces.

Finds the GENERATION observation named "synthesis" in each trace and
extracts the system prompt, user message, and production output.

This is the highest-risk component — if the observation name changes
in daily_report_graph.py, extraction fails. Guard with assert + loud log.
"""

import logging
import re
from datetime import datetime
from typing import Optional

from agent.evals.state import CapturedTrace, SynthesisInput

logger = logging.getLogger(__name__)

# Observation filter: type + name used in agent/llm.py chat() → @observe(as_type="generation")
# agent_name="synthesis" in daily_report_graph.py synthesize()
_SYNTHESIS_OBS_NAMES = {"synthesis", "synthesis/llm"}
_SYNTHESIS_OBS_TYPE = "GENERATION"

# Date extraction: try trace name first (daily-report-YYYYMMDD-HHMMSS-hex)
_TRACE_DATE_RE = re.compile(r"daily-report-(\d{4})(\d{2})(\d{2})")


def _extract_date(trace) -> str:
    """Best-effort date extraction from trace name or timestamp."""
    if trace.name:
        m = _TRACE_DATE_RE.search(trace.name)
        if m:
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    if trace.timestamp:
        ts = trace.timestamp
        if isinstance(ts, datetime):
            return ts.strftime("%Y-%m-%d")
        return str(ts)[:10]
    return "unknown"


def extract_synthesis_from_trace(trace) -> Optional[CapturedTrace]:
    """Extract CapturedTrace from a full Langfuse trace (with observations).

    Args:
        trace: A Langfuse TraceWithFullDetails (has .observations list)

    Returns:
        CapturedTrace if synthesis generation found, None otherwise.
    """
    observations = getattr(trace, "observations", [])
    if not observations:
        logger.warning("Trace %s has no observations — skipping", trace.id)
        return None

    # Find the synthesis generation
    synthesis_obs = None
    for obs in observations:
        if (
            getattr(obs, "type", None) == _SYNTHESIS_OBS_TYPE
            and getattr(obs, "name", None) in _SYNTHESIS_OBS_NAMES
        ):
            synthesis_obs = obs
            break

    if synthesis_obs is None:
        obs_summary = [
            (getattr(o, "name", "?"), getattr(o, "type", "?"))
            for o in observations
        ]
        logger.error(
            "Trace %s: no GENERATION named 'synthesis' found. "
            "Observations: %s — extractor may be stale (check daily_report_graph.py agent_name)",
            trace.id,
            obs_summary,
        )
        return None

    # Validate input shape: expect [{"role": "system", ...}, {"role": "user", ...}]
    inp = synthesis_obs.input
    if not isinstance(inp, list) or len(inp) < 2:
        logger.error(
            "Trace %s: synthesis input is not a 2-element list (got %s) — shape changed?",
            trace.id,
            type(inp).__name__,
        )
        return None

    system_msg = inp[0]
    user_msg = inp[1]

    if not isinstance(system_msg, dict) or system_msg.get("role") != "system":
        logger.error("Trace %s: synthesis input[0] is not a system message", trace.id)
        return None
    if not isinstance(user_msg, dict) or user_msg.get("role") != "user":
        logger.error("Trace %s: synthesis input[1] is not a user message", trace.id)
        return None

    system_content = system_msg.get("content", "")
    user_content = user_msg.get("content", "")
    output = synthesis_obs.output or ""

    if not system_content or not user_content:
        logger.error("Trace %s: synthesis input has empty system or user content", trace.id)
        return None

    date = _extract_date(trace)
    model = getattr(synthesis_obs, "model", None) or "unknown"

    synthesis_input = SynthesisInput(
        synthesis_system_prompt=system_content,
        synthesis_user_message=user_content,
        date=date,
        synthesis_prompt_version=None,  # not tracked in observation metadata currently
    )

    return CapturedTrace(
        trace_id=trace.id,
        trace_name=getattr(trace, "name", "") or "",
        synthesis_input=synthesis_input,
        final_report=output if isinstance(output, str) else str(output),
        model=model,
        date=date,
    )
