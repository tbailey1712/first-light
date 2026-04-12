"""
Node 1: Collect traces from Langfuse.

Fetches recent daily-report traces, filters out already-processed ones,
and extracts SynthesisInput from each.
"""

import logging
from datetime import datetime, timedelta, timezone

from agent.evals.registry import get_seen_trace_ids, mark_traces_seen
from agent.evals.state import EvalState
from agent.evals.trace_extractor import extract_synthesis_from_trace
from agent.langfuse_integration import get_langfuse_client

logger = logging.getLogger(__name__)


def collect_traces(state: EvalState) -> dict:
    """Fetch daily-report traces from Langfuse, extract synthesis inputs."""
    days = state["days"]
    lf = get_langfuse_client()

    # Fetch traces tagged "daily-report" within the lookback window
    from_ts = datetime.now(timezone.utc) - timedelta(days=days)

    logger.info("Collecting daily-report traces from past %d days...", days)

    all_traces = []
    page = 1
    try:
        while True:
            resp = lf.api.trace.list(
                tags=["daily-report"],
                from_timestamp=from_ts,
                limit=50,
                page=page,
            )
            batch = resp.data if hasattr(resp, "data") else resp
            if not batch:
                break
            all_traces.extend(batch)
            if len(batch) < 50:
                break
            page += 1
    except Exception as e:
        logger.error("Failed to list traces from Langfuse: %s", e)
        if not all_traces:
            return {"captured_traces": []}

    logger.info("Found %d daily-report traces", len(all_traces))

    # Defensive: exclude any eval traces that might appear (shouldn't have the tag, but be safe)
    all_traces = [
        t for t in all_traces
        if not (getattr(t, "name", "") or "").startswith("eval-")
    ]

    # Filter out already-seen traces
    seen = get_seen_trace_ids()
    new_traces = [t for t in all_traces if t.id not in seen]
    logger.info("After dedup: %d new traces (%d already seen)", len(new_traces), len(all_traces) - len(new_traces))

    if not new_traces:
        return {"captured_traces": []}

    # Extract synthesis inputs from each trace
    captured = []
    for trace_stub in new_traces:
        # Fetch full trace with observations
        try:
            full_trace = lf.api.trace.get(trace_stub.id)
        except Exception as e:
            logger.error("Failed to fetch trace %s: %s", trace_stub.id, e)
            continue

        result = extract_synthesis_from_trace(full_trace)
        if result is not None:
            captured.append(result)
        else:
            logger.warning("Trace %s: extraction returned None — skipping", trace_stub.id)

    # Mark all fetched traces as seen (even failed extractions — don't retry broken traces)
    mark_traces_seen([t.id for t in new_traces])

    logger.info("Captured %d synthesis inputs from %d new traces", len(captured), len(new_traces))
    return {"captured_traces": captured}
