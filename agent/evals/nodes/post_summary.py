"""
Node 5: Post eval summary to Slack.

Formats a compact table of per-experiment scores, regression flags,
and champion status.
"""

import asyncio
import logging
from typing import Optional

from agent.evals.state import EvalState

logger = logging.getLogger(__name__)


def _format_summary(state: EvalState) -> str:
    """Build the Slack summary message."""
    scores = state["experiment_scores"]
    regressions = state["regressions"]
    champion = state.get("new_champion")
    urls = state.get("experiment_urls", {})
    n_traces = len(state.get("captured_traces", []))
    n_stored = state.get("dataset_items_stored", 0)

    lines = [
        f"*First Light Eval Complete* — {n_traces} trace(s) collected, {n_stored} stored, {len(scores)} experiment(s)",
        "",
    ]

    if not scores:
        lines.append("_No experiments produced results._")
        return "\n".join(lines)

    # Header row
    lines.append(
        "```"
    )
    lines.append(
        f"{'Experiment':<20} {'Compl':>6} {'Action':>6} {'Sev':>6} {'Fmt':>6} {'FP↓':>6} {'Score':>6}"
    )
    lines.append(f"{'-' * 20} {'-' * 6} {'-' * 6} {'-' * 6} {'-' * 6} {'-' * 6} {'-' * 6}")

    for exp_id, s in scores.items():
        lines.append(
            f"{exp_id:<20} {s.get('completeness', 0):.2f}   {s.get('actionability', 0):.2f}   "
            f"{s.get('severity_accuracy', 0):.2f}   {s.get('format', 0):.2f}   "
            f"{s.get('false_positive_rate', 0):.2f}   {s.get('composite', 0):.2f}"
        )
    lines.append("```")

    # Regressions
    if regressions:
        reg_strs = [f"`{r['dimension']}` ({r['delta']:+.3f})" for r in regressions if r["regressed"]]
        min_strs = [f"`{r['dimension']}` ({r['current']:.2f})" for r in regressions if r["below_minimum"]]
        if reg_strs:
            lines.append(f"*Regressions:* {', '.join(reg_strs)}")
        if min_strs:
            lines.append(f"*Below minimum:* {', '.join(min_strs)}")
    else:
        lines.append("*Regressions:* None")

    # Champion
    if champion:
        composite = scores.get(champion, {}).get("composite", 0)
        lines.append(f"*New champion:* `{champion}` ({composite:.2f})")

    # Langfuse links
    for exp_id, url in urls.items():
        if url:
            lines.append(f"<{url}|Review {exp_id} in Langfuse>")

    return "\n".join(lines)


def post_summary(state: EvalState) -> dict:
    """Post eval summary to Slack reports channel."""
    summary = _format_summary(state)
    logger.info("Eval summary:\n%s", summary)

    try:
        from agent.notifications.slack import build_slack_bot_channel

        channel = build_slack_bot_channel()
        if not channel:
            logger.warning("Slack bot channel not configured — summary not posted")
            return {"summary_posted": False}

        # Graph nodes run synchronously (LangGraph invoke). When called from
        # the scheduler's run_in_executor, we're on a worker thread with no
        # running event loop, so asyncio.run() is safe.
        asyncio.run(channel.send_alert(summary))

        logger.info("Eval summary posted to Slack")
        return {"summary_posted": True}
    except Exception as e:
        logger.error("Failed to post eval summary to Slack: %s", e)
        return {"summary_posted": False}
