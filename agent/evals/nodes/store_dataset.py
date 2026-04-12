"""
Node 2: Store captured traces as Langfuse dataset items.

Creates the dataset if it doesn't exist, then upserts one item per
captured trace. Uses trace_id as item ID for idempotency.
"""

import logging

from agent.evals.config import DATASET_NAME
from agent.evals.state import EvalState
from agent.langfuse_integration import get_langfuse_client

logger = logging.getLogger(__name__)


def store_dataset(state: EvalState) -> dict:
    """Create/update Langfuse dataset items from captured traces."""
    traces = state["captured_traces"]
    if not traces:
        logger.info("No new traces to store — skipping dataset update")
        return {"dataset_name": DATASET_NAME, "dataset_items_stored": 0}

    lf = get_langfuse_client()

    # Ensure dataset exists
    try:
        lf.get_dataset(DATASET_NAME)
    except Exception:
        logger.info("Creating dataset '%s'", DATASET_NAME)
        lf.create_dataset(name=DATASET_NAME)

    stored = 0
    for trace in traces:
        try:
            lf.create_dataset_item(
                dataset_name=DATASET_NAME,
                id=trace["trace_id"],  # idempotent — same trace_id = same item
                input=trace["synthesis_input"],
                expected_output=trace["final_report"],
                metadata={
                    "date": trace["date"],
                    "model": trace["model"],
                    "trace_name": trace["trace_name"],
                    "source_trace_id": trace["trace_id"],
                },
                source_trace_id=trace["trace_id"],
            )
            stored += 1
        except Exception as e:
            logger.error("Failed to store dataset item for trace %s: %s", trace["trace_id"], e)

    logger.info("Stored %d/%d dataset items in '%s'", stored, len(traces), DATASET_NAME)
    return {"dataset_name": DATASET_NAME, "dataset_items_stored": stored}
