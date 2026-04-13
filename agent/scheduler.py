"""
First Light Agent Scheduler

Runs the daily threat assessment report on a schedule and keeps the
agent service alive for on-demand queries via the MCP server.

Schedule:
  - Daily report: 08:00 local time
  - Infra health check: every 20 minutes (fires Pushover/Slack on critical)
"""

import asyncio
import json
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


async def run_eval_agent():
    """Run the eval lifecycle — replay synthesis, judge, detect regressions."""
    logger.info("Starting eval agent...")
    try:
        from agent.evals.eval_agent import run_eval_agent as _run_eval
        await asyncio.get_event_loop().run_in_executor(None, lambda: _run_eval(days=7))
        logger.info("Eval agent complete")
    except Exception as e:
        logger.error("Eval agent failed: %s", e, exc_info=True)
        await _notify_failure("Eval agent", str(e))


async def run_infra_health_check():
    """
    Proactive infrastructure health check — runs every 20 minutes.

    Fires a Pushover + Slack alert immediately when a collector transitions
    to critical. Redis is used for dedup: each critical item is silenced for
    4 hours after the first alert to prevent spam.
    """
    # Silencing TTL: re-alert no more than once per 4 hours per item
    SILENCE_TTL = 4 * 3600
    REDIS_KEY_PREFIX = "fl:health:alerted:"

    try:
        import agent.tools.infra_health as _ih
        # Call the underlying function directly (not the langchain StructuredTool wrapper)
        _fn = _ih.query_reporting_infra_health.func if hasattr(_ih.query_reporting_infra_health, "func") else _ih.query_reporting_infra_health
        raw = await asyncio.get_event_loop().run_in_executor(None, _fn)
        data = json.loads(raw if isinstance(raw, str) else raw.content)
    except Exception as e:
        logger.error("Infra health check failed: %s", e)
        return

    overall = data.get("overall", "ok")
    if overall == "ok":
        logger.debug("Infra health check: all ok")
        return

    critical_items: list[str] = data.get("critical", [])
    warning_items: list[str] = data.get("warning", [])

    if not critical_items:
        logger.debug("Infra health check: warnings only (%s), no alert", warning_items)
        return

    # Dedup via Redis — only alert for items not already silenced
    r = await asyncio.get_event_loop().run_in_executor(None, _get_redis_client)
    new_criticals: list[str] = []

    for item in critical_items:
        key = f"{REDIS_KEY_PREFIX}{item}"
        already_alerted = False
        if r is not None:
            try:
                already_alerted = bool(r.get(key))
            except Exception:
                pass
        if not already_alerted:
            new_criticals.append(item)
            if r is not None:
                try:
                    r.set(key, "1", ex=SILENCE_TTL)
                except Exception:
                    pass

    if not new_criticals:
        logger.debug("Infra health check: critical items all silenced (%s)", critical_items)
        return

    # Build alert message
    lines = ["*First Light — Infrastructure Alert*", ""]
    lines.append(f"*Critical (data collection down):* {', '.join(new_criticals)}")
    if warning_items:
        lines.append(f"*Warning:* {', '.join(warning_items)}")

    # Add detail per critical item from full check data
    detail_sections = (
        data.get("metric_collectors", [])
        + data.get("containers", [])
        + [data.get("log_ingestion", {}), data.get("ntopng", {})]
    )
    for section in detail_sections:
        name = section.get("collector") or section.get("container", "")
        if section.get("status") == "critical" and name in new_criticals:
            detail = section.get("detail", "")
            if detail:
                lines.append(f"  • {name}: {detail}")

    lines.append("")
    lines.append("_Domain agents may produce findings based on incomplete data._")
    message = "\n".join(lines)

    logger.warning("Infra health alert: %s", new_criticals)
    try:
        from agent.notifications import broadcast_alert
        await broadcast_alert(message)
    except Exception as e:
        logger.error("Failed to send infra health alert: %s", e)


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

    health_interval = int(os.getenv("HEALTH_CHECK_INTERVAL_MINUTES", "20"))

    scheduler = AsyncIOScheduler(timezone=tz)
    scheduler.add_job(
        run_daily_report,
        trigger=CronTrigger(hour=report_hour, minute=report_minute, timezone=tz),
        id="daily_report",
        name="Daily Threat Assessment",
        max_instances=1,
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        run_infra_health_check,
        trigger="interval",
        minutes=health_interval,
        id="infra_health_check",
        name="Infrastructure Health Monitor",
        max_instances=1,
        misfire_grace_time=300,
        next_run_time=datetime.now(),  # Run immediately on startup too
    )
    eval_hour = int(os.getenv("EVAL_HOUR", "10"))
    eval_minute = int(os.getenv("EVAL_MINUTE", "0"))
    if os.getenv("EVAL_ENABLED", "false").lower() == "true":
        scheduler.add_job(
            run_eval_agent,
            trigger=CronTrigger(hour=eval_hour, minute=eval_minute, timezone=tz),
            id="eval_agent",
            name="Synthesis Eval Lifecycle",
            max_instances=1,
            misfire_grace_time=3600,
        )
        logger.info(f"Eval agent scheduled at {eval_hour:02d}:{eval_minute:02d} {tz}")
    scheduler.start()
    logger.info("Scheduler running. Health check every %dm.", health_interval)

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
