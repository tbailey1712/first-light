#!/usr/bin/env python3
"""
Daily Threat Assessment Report Generator

Runs the 6-domain multi-agent pipeline to analyse the past 24 hours and
produce a security + health report, then delivers it via Telegram.

Pipeline:
  6 domain agents (parallel) → synthesis agent → markdown report → Telegram
"""

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import os
import logging

logger = logging.getLogger(__name__)

REPORTS_BASE = os.getenv("FIRST_LIGHT_REPORTS_DIR", str(Path(__file__).parent.parent.parent / "reports"))
REPORTS_DIR = Path(REPORTS_BASE) / "daily"


def ensure_directories():
    """Create report directory structure."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def get_report_path(date: str) -> Path:
    """Get file path for a report."""
    year, month, _ = date.split("-")
    report_dir = REPORTS_DIR / year / month
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir / f"{date}_daily_report.md"


def get_metrics_path(date: str) -> Path:
    """Get file path for metrics JSON."""
    year, month, _ = date.split("-")
    report_dir = REPORTS_DIR / year / month
    return report_dir / f"{date}_metrics.json"


async def generate_daily_report(hours: int = 24) -> Dict[str, Any]:
    """
    Generate the daily report using the multi-agent pipeline.

    Runs in a thread executor because the domain agents and synthesis
    agent are synchronous (LiteLLM / LangChain calls).

    Returns:
        Dict with report_id, date, report_path, report_text
    """
    from agent.graphs.daily_report_graph import generate_daily_report as _run_graph

    ensure_directories()

    report_id = str(uuid.uuid4())
    report_date = datetime.now().strftime("%Y-%m-%d")

    logger.info(f"Generating daily report {report_id} for {report_date}")

    # Run the synchronous multi-agent pipeline in a thread so we don't
    # block the asyncio event loop.
    loop = asyncio.get_event_loop()
    report_body = await loop.run_in_executor(None, _run_graph, hours)

    # Build the full report with a standard header
    report_header = (
        f"# First Light — Daily Report\n"
        f"**Date:** {report_date}  \n"
        f"**Report ID:** {report_id}  \n"
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n"
        f"\n---\n\n"
    )
    full_report = report_header + report_body

    # Save report file
    report_path = get_report_path(report_date)
    report_path.write_text(full_report)
    logger.info(f"Report saved: {report_path}")

    # Save lightweight metrics JSON (placeholder — extend as needed)
    metrics = {"report_id": report_id, "report_type": "daily", "date": report_date,
                "generated_at": datetime.now().isoformat(), "report_path": str(report_path)}
    get_metrics_path(report_date).write_text(json.dumps(metrics, indent=2))

    return {
        "report_id": report_id,
        "date": report_date,
        "report_path": str(report_path),
        "report_text": full_report,
    }


async def send_report_notification(report: Dict[str, Any]):
    """Send report via Telegram."""
    import httpx
    from agent.config import get_config

    config = get_config()
    if not config.telegram_bot_token or not config.telegram_chat_id:
        logger.warning("Telegram not configured — skipping notification")
        return

    report_text = report["report_text"]

    # Telegram messages cap at 4096 chars; send summary if longer
    if len(report_text) > 4000:
        lines = report_text.split("\n")
        truncated = "\n".join(lines[:60])
        message = f"{truncated}\n\n_… Report truncated …_\n\n📄 Full report: `{report['report_path']}`"
    else:
        message = report_text

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage",
                json={
                    "chat_id": config.telegram_chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True,
                },
            )
        if resp.status_code == 200:
            logger.info(f"Report sent to Telegram chat {config.telegram_chat_id}")
        else:
            logger.warning(f"Telegram send failed: {resp.status_code} — {resp.text[:200]}")
    except Exception as e:
        logger.error(f"Error sending to Telegram: {e}")

    logger.info(f"Report saved locally: {report['report_path']}")


async def main():
    """Entry point for manual runs."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    ensure_directories()
    try:
        report = await generate_daily_report()
        await send_report_notification(report)
        print(f"\n✅ Daily report complete: {report['report_path']}")
    except Exception as e:
        logger.error(f"Daily report failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    asyncio.run(main())
