"""
First Light Agent Scheduler

Runs the daily threat assessment report on a schedule and keeps the
agent service alive for on-demand queries via the MCP server.

Schedule:
  - Daily report: 08:00 local time
  - (future) Weekly rollup: Sunday 20:00
"""

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("scheduler")


async def run_daily_report():
    """Run the daily threat assessment report."""
    logger.info("Starting daily threat assessment report...")
    try:
        from agent.reports.daily_threat_assessment import generate_daily_report, send_report_notification
        report = await generate_daily_report()
        await send_report_notification(report)
        logger.info(f"Daily report complete: {report['report_path']}")
    except Exception as e:
        logger.error(f"Daily report failed: {e}", exc_info=True)
        # Send failure notice to Telegram
        await _notify_failure("Daily report", str(e))


async def _notify_failure(job_name: str, error: str):
    """Send a failure notification to Telegram."""
    try:
        import httpx
        from agent.config import get_config
        config = get_config()
        if not config.telegram_bot_token or not config.telegram_chat_id:
            return
        async with httpx.AsyncClient() as client:
            await client.post(
                f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage",
                json={
                    "chat_id": config.telegram_chat_id,
                    "text": f"🔴 *First Light scheduler error*\n*Job:* {job_name}\n*Error:* `{error[:200]}`",
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
    except Exception:
        pass


def main():
    """Entry point: start the scheduler."""
    tz = os.getenv("TZ", "America/Chicago")
    report_hour = int(os.getenv("DAILY_REPORT_HOUR", "8"))
    report_minute = int(os.getenv("DAILY_REPORT_MINUTE", "0"))

    logger.info(f"First Light scheduler starting (tz={tz})")
    logger.info(f"Daily report scheduled at {report_hour:02d}:{report_minute:02d} {tz}")

    scheduler = AsyncIOScheduler(timezone=tz)

    scheduler.add_job(
        run_daily_report,
        trigger=CronTrigger(hour=report_hour, minute=report_minute, timezone=tz),
        id="daily_report",
        name="Daily Threat Assessment",
        max_instances=1,
        misfire_grace_time=3600,  # Run up to 1h late if missed
    )

    loop = asyncio.get_event_loop()

    def shutdown(sig, frame):
        logger.info(f"Received {signal.Signals(sig).name}, shutting down...")
        scheduler.shutdown(wait=False)
        loop.stop()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    scheduler.start()
    logger.info("Scheduler running. Press Ctrl+C to stop.")

    # Run the daily report immediately on startup if RUN_ON_STARTUP=true
    if os.getenv("RUN_ON_STARTUP", "false").lower() == "true":
        logger.info("RUN_ON_STARTUP=true — running daily report now...")
        loop.run_until_complete(run_daily_report())

    try:
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped.")


if __name__ == "__main__":
    main()
