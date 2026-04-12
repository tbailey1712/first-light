"""
Eval Agent — LangGraph graph for the Langfuse eval lifecycle.

Flow:
  START
    └─ collect_traces     (fetch + extract synthesis inputs from Langfuse)
         └─ store_dataset  (upsert items into Langfuse dataset)
              └─ run_experiments  (replay synthesis + judge per experiment config)
                   └─ detect_regressions  (compare to baseline, update champion)
                        └─ post_summary  (Slack table)
                             └─ END

Conditional: if collect_traces returns no new traces, skip straight to
run_experiments (re-evaluate existing dataset items).

Public interface:
    run_eval_agent(days=7) -> EvalState
"""

import logging
import uuid
from datetime import datetime, timezone

from langgraph.graph import StateGraph, START, END
from langfuse import observe, get_client as get_langfuse_client, LangfuseOtelSpanAttributes
from opentelemetry import trace as otel_trace

from agent.evals.config import DATASET_NAME
from agent.evals.nodes.collect_traces import collect_traces
from agent.evals.nodes.detect_regressions import detect_regressions
from agent.evals.nodes.post_summary import post_summary
from agent.evals.nodes.run_experiments import run_experiments
from agent.evals.nodes.store_dataset import store_dataset
from agent.evals.state import EvalState

logger = logging.getLogger(__name__)


def _should_store(state: EvalState) -> str:
    """Route: if new traces were captured, store them; otherwise skip to experiments."""
    if state.get("captured_traces"):
        return "store_dataset"
    return "run_experiments"


# ── Graph ────────────────────────────────────────────────────────────────────

_builder = StateGraph(EvalState)
_builder.add_node("collect_traces", collect_traces)
_builder.add_node("store_dataset", store_dataset)
_builder.add_node("run_experiments", run_experiments)
_builder.add_node("detect_regressions", detect_regressions)
_builder.add_node("post_summary", post_summary)

_builder.add_edge(START, "collect_traces")
_builder.add_conditional_edges(
    "collect_traces",
    _should_store,
    {"store_dataset": "store_dataset", "run_experiments": "run_experiments"},
)
_builder.add_edge("store_dataset", "run_experiments")
_builder.add_edge("run_experiments", "detect_regressions")
_builder.add_edge("detect_regressions", "post_summary")
_builder.add_edge("post_summary", END)

graph = _builder.compile()


# ── Public entrypoint ────────────────────────────────────────────────────────

@observe(as_type="span", capture_input=False, capture_output=False)
def run_eval_agent(days: int = 7) -> dict:
    """Run the full eval lifecycle.

    Args:
        days: How many days of traces to look back (default 7).

    Returns:
        Final EvalState dict.
    """
    start = datetime.now(timezone.utc)
    session_id = f"eval-{start.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    logger.info("=== Eval Agent Start (days=%d, session=%s) ===", days, session_id)

    # Tag the trace so collect_traces can exclude eval traces
    lf = get_langfuse_client()
    span = otel_trace.get_current_span()
    span.set_attribute(LangfuseOtelSpanAttributes.TRACE_NAME, session_id)
    span.set_attribute(LangfuseOtelSpanAttributes.TRACE_SESSION_ID, session_id)
    span.set_attribute(LangfuseOtelSpanAttributes.TRACE_TAGS, ["eval"])
    lf.update_current_span(name="eval-agent", input={"days": days})

    initial_state: EvalState = {
        "days": days,
        "captured_traces": [],
        "dataset_name": DATASET_NAME,
        "dataset_items_stored": 0,
        "experiment_scores": {},
        "experiment_urls": {},
        "regressions": [],
        "new_champion": None,
        "summary_posted": False,
    }

    result = graph.invoke(initial_state)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    logger.info(
        "=== Eval Agent Complete in %.1fs — %d experiments, %d regressions ===",
        elapsed,
        len(result.get("experiment_scores", {})),
        len(result.get("regressions", [])),
    )

    lf.update_current_span(output={
        "experiments": len(result.get("experiment_scores", {})),
        "regressions": len(result.get("regressions", [])),
        "champion": result.get("new_champion"),
    })
    lf.flush()

    return result
