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
from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("scheduler")

REPORT_LOCK_KEY = "report:lock:daily"
REPORT_LOCK_TTL = 600  # 10 minutes

# Keep private aliases for backward compatibility within this module
_REPORT_LOCK_KEY = REPORT_LOCK_KEY
_REPORT_LOCK_TTL = REPORT_LOCK_TTL


def _get_redis_client():
    """Return a Redis client, or None if Redis is unavailable."""
    try:
        import redis
        url = os.getenv("REDIS_URL", "redis://fl-redis:6379/0")
        r = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
        r.ping()
        return r
    except Exception as e:
        logger.warning("Redis unavailable (%s) — lock guard disabled", e)
        return None


async def run_daily_report():
    """Run the daily threat assessment report, guarded by a Redis distributed lock."""
    # Best-effort distributed lock — prevents duplicate runs on container restart.
    # If Redis is unavailable, we run anyway (APScheduler's max_instances=1 is
    # still in effect for same-process duplicate prevention).
    r = await asyncio.get_event_loop().run_in_executor(None, _get_redis_client)
    if r is not None:
        acquired = r.set(_REPORT_LOCK_KEY, "1", nx=True, ex=_REPORT_LOCK_TTL)
        if not acquired:
            logger.warning("Daily report already running (Redis lock held) — skipping this run")
            return
    else:
        r = None  # Proceed without lock

    logger.info("Starting daily threat assessment report...")
    try:
        from agent.reports.daily_threat_assessment import generate_daily_report
        from agent.notifications import broadcast_report
        report = await generate_daily_report()
        await broadcast_report(report)
        logger.info(f"Daily report complete: {report['report_path']}")
    except Exception as e:
        logger.error(f"Daily report failed: {e}", exc_info=True)
        await _notify_failure("Daily report", str(e))
    finally:
        if r is not None:
            try:
                r.delete(_REPORT_LOCK_KEY)
            except Exception:
                pass


async def _notify_failure(job_name: str, error: str):
    """Send a failure alert to all registered notification channels."""
    try:
        from agent.notifications import broadcast_alert
        message = f"🔴 *First Light scheduler error*\n*Job:* {job_name}\n*Error:* `{error[:200]}`"
        await broadcast_alert(message)
    except Exception:
        pass


async def _run():
    """Async main loop."""
    tz = os.getenv("TZ", "America/Chicago")
    report_hour = int(os.getenv("DAILY_REPORT_HOUR", "8"))
    report_minute = int(os.getenv("DAILY_REPORT_MINUTE", "0"))

    # Initialise notification channels once at startup
    from agent.notifications import register_defaults
    await register_defaults()

    logger.info(f"First Light scheduler starting (tz={tz})")
    logger.info(f"Daily report scheduled at {report_hour:02d}:{report_minute:02d} {tz}")

    scheduler = AsyncIOScheduler(timezone=tz)
    scheduler.add_job(
        run_daily_report,
        trigger=CronTrigger(hour=report_hour, minute=report_minute, timezone=tz),
        id="daily_report",
        name="Daily Threat Assessment",
        max_instances=1,
        misfire_grace_time=3600,
    )
    scheduler.start()
    logger.info("Scheduler running.")

    # Run immediately on startup if requested
    if os.getenv("RUN_ON_STARTUP", "false").lower() == "true":
        logger.info("RUN_ON_STARTUP=true — running daily report now...")
        await run_daily_report()

    # Keep alive until SIGTERM/SIGINT
    stop_event = asyncio.Event()

    def _stop(sig, frame):
        logger.info(f"Received {signal.Signals(sig).name}, shutting down...")
        scheduler.shutdown(wait=False)
        stop_event.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    await stop_event.wait()
    logger.info("Scheduler stopped.")


def main():
    asyncio.run(_run())


if __name__ == "__main__":
    main()
