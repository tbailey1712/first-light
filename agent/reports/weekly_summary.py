"""
Weekly Trend Summary

Reads the last N daily reports from disk, identifies recurring issues,
directional trends, and action items that have gone unaddressed across
multiple daily runs. Single LLM call — no tool loop needed.
"""

import asyncio
import logging
import os
import uuid
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

from agent.llm import chat

logger = logging.getLogger(__name__)

REPORTS_BASE = os.getenv(
    "FIRST_LIGHT_REPORTS_DIR",
    str(Path(__file__).parent.parent.parent / "reports"),
)
DAILY_REPORTS_DIR = Path(REPORTS_BASE) / "daily"
WEEKLY_REPORTS_DIR = Path(REPORTS_BASE) / "weekly"


def _load_last_n_daily_reports(n: int = 7) -> list[tuple[str, str]]:
    """Return [(date_str, content), ...] for the last N daily reports found on disk.

    Searches backwards from yesterday, skipping missing dates, returning
    results in chronological order (oldest first).
    """
    reports = []
    today = date.today()
    for i in range(1, n + 14):  # look back up to n+14 days to find n reports
        d = today - timedelta(days=i)
        path = (
            DAILY_REPORTS_DIR
            / str(d.year)
            / f"{d.month:02d}"
            / f"{d}_daily_report.md"
        )
        if path.exists():
            reports.append((str(d), path.read_text()))
            if len(reports) == n:
                break
    return list(reversed(reports))  # oldest → newest


def generate_weekly_summary(days: int = 7, session_id: Optional[str] = None) -> dict:
    """Generate a weekly trend summary from the last N daily reports.

    Args:
        days:       Number of daily reports to analyse (default: 7)
        session_id: Langfuse session ID for trace grouping

    Returns:
        Dict with report_id, date, date_range, days_analyzed, report_path, report_text
    """
    from agent.langfuse_integration import get_prompt_manager

    reports = _load_last_n_daily_reports(days)
    if not reports:
        raise RuntimeError(f"No daily reports found in {DAILY_REPORTS_DIR}")

    # Build context block — each report labelled with its date
    context_parts = []
    for date_str, content in reports:
        context_parts.append(
            f"{'=' * 60}\nDAILY REPORT — {date_str}\n{'=' * 60}\n{content}"
        )
    context = "\n\n".join(context_parts)

    # Load prompt from Langfuse
    pm = get_prompt_manager()
    try:
        prompt_obj = pm.get_prompt("first-light-weekly", label="production")
        system_prompt = prompt_obj.prompt
    except Exception as e:
        raise ValueError(
            f"first-light-weekly prompt not found in Langfuse (label=production): {e}"
        )

    date_range = f"{reports[0][0]} to {reports[-1][0]}"
    user_message = (
        f"Analyse these {len(reports)} daily reports covering {date_range} "
        f"and produce the weekly summary."
    )

    logger.info(
        "Generating weekly summary from %d reports (%s)", len(reports), date_range
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"{user_message}\n\n{context}"},
    ]

    response = chat(
        messages,
        agent_type="weekly",
        session_id=session_id or f"weekly-{date.today()}",
        agent_name="weekly_summary",
    )
    summary = response.choices[0].message.content or "[no content returned]"

    # Save to disk
    today_str = str(date.today())
    out_dir = WEEKLY_REPORTS_DIR / str(date.today().year) / f"{date.today().month:02d}"
    out_dir.mkdir(parents=True, exist_ok=True)

    report_id = str(uuid.uuid4())
    header = (
        f"# First Light — Weekly Summary\n"
        f"**Period:** {date_range}  \n"
        f"**Reports analysed:** {len(reports)}  \n"
        f"**Report ID:** {report_id}  \n"
        f"**Generated:** {today_str}  \n\n---\n\n"
    )
    full_report = header + summary
    out_path = out_dir / f"{today_str}_weekly_summary.md"
    out_path.write_text(full_report)
    logger.info("Weekly summary saved: %s", out_path)

    return {
        "report_id": report_id,
        "date": today_str,
        "date_range": date_range,
        "days_analyzed": len(reports),
        "report_path": str(out_path),
        "report_text": full_report,
    }


async def generate_weekly_summary_async(days: int = 7) -> dict:
    """Async wrapper — runs the synchronous LLM call in a thread executor."""
    return await asyncio.get_running_loop().run_in_executor(
        None, generate_weekly_summary, days
    )
