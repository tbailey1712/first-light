"""
Ingestion freshness watchdog.

Detects the SigNoz otel-collector *log-pipeline wedge* and auto-recovers it.

Failure mode (see memory: project_log_ingestion_wedge):
  A transient ClickHouse slowdown (e.g. the daily ~18:05 UTC metrics-merge
  window) pushes the log `clickhouselogsexporter` insert past its timeout. The
  failed insert can leave the log pipeline permanently wedged — logs stop
  flowing while metrics keep flowing through the *same* collector — and it does
  NOT self-recover. Docker reports the container "healthy" the whole time.

Strategy:
  Every few minutes, compare log freshness (signoz_logs) against metric
  freshness (signoz_metrics). The wedge signature is *logs stale AND metrics
  fresh*. On that signature, restart the collector (via the Docker socket) and
  alert. Guardrails (min gap between restarts, daily cap) prevent restart loops,
  and if metrics are ALSO stale we alert only — that is a broader ClickHouse /
  collector outage a restart will not fix.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger("watchdog")

# --- Thresholds (minutes) ---------------------------------------------------
LOG_STALE_MIN = int(os.getenv("WATCHDOG_LOG_STALE_MIN", "25"))
METRIC_FRESH_MIN = int(os.getenv("WATCHDOG_METRIC_FRESH_MIN", "10"))

# --- Guardrails -------------------------------------------------------------
MIN_RESTART_GAP_MIN = int(os.getenv("WATCHDOG_MIN_RESTART_GAP_MIN", "30"))
MAX_RESTARTS_PER_DAY = int(os.getenv("WATCHDOG_MAX_RESTARTS_PER_DAY", "4"))

# --- Target / transport -----------------------------------------------------
COLLECTOR_CONTAINER = os.getenv("WATCHDOG_COLLECTOR_CONTAINER", "signoz-otel-collector")
DOCKER_SOCK = os.getenv("WATCHDOG_DOCKER_SOCK", "/var/run/docker.sock")

# Look-back windows for the freshness queries. If the newest row is OLDER than
# the window, the query returns no rows — we treat that as "stale beyond
# window" (a large lag), NOT "unknown".
_LOG_WINDOW_S = 4 * 3600
_METRIC_WINDOW_S = 3600

_REDIS_LAST_RESTART = "watchdog:last_restart_ts"
_REDIS_DAY_PREFIX = "watchdog:restarts:"


@dataclass
class Freshness:
    """Result of measuring pipeline freshness. lag is seconds; None = unknown."""

    log_lag_s: int | None
    metric_lag_s: int | None


@dataclass
class Decision:
    action: str  # "ok" | "restart" | "alert_only" | "skip"
    reason: str


def decide(
    fresh: Freshness,
    *,
    log_stale_s: int,
    metric_fresh_s: int,
    can_restart: bool,
) -> Decision:
    """Pure decision logic — no I/O, fully unit-testable.

    - log lag unknown            -> skip   (can't reach ClickHouse; don't act blind)
    - logs fresh                 -> ok
    - logs stale, metrics fresh  -> restart (the wedge signature) or alert_only
                                    if a guardrail blocks the restart
    - logs stale, metrics not    -> alert_only (broader outage; restart won't help)
    """
    if fresh.log_lag_s is None:
        return Decision("skip", "log freshness unknown (ClickHouse unreachable)")

    if fresh.log_lag_s < log_stale_s:
        return Decision("ok", f"logs fresh ({fresh.log_lag_s}s lag)")

    metrics_fresh = fresh.metric_lag_s is not None and fresh.metric_lag_s < metric_fresh_s
    if not metrics_fresh:
        metric_desc = "unknown" if fresh.metric_lag_s is None else f"{fresh.metric_lag_s}s"
        return Decision(
            "alert_only",
            f"logs stale ({fresh.log_lag_s}s) AND metrics not fresh ({metric_desc}) "
            "— broader outage, collector restart will not help",
        )

    reason = (
        f"log-pipeline wedge: logs stale {fresh.log_lag_s}s while metrics fresh "
        f"{fresh.metric_lag_s}s"
    )
    if not can_restart:
        return Decision("alert_only", reason + " — restart suppressed by guardrail")
    return Decision("restart", reason)


# --- I/O helpers ------------------------------------------------------------

def _measure_freshness() -> Freshness:
    """Query ClickHouse for log + metric lag in seconds."""
    from agent.tools.infra_health import _clickhouse_query

    log_sql = f"""
        SELECT toUnixTimestamp(now()) - toUnixTimestamp(toDateTime(max(timestamp) / 1000000000)) AS lag_s
        FROM signoz_logs.distributed_logs_v2
        WHERE timestamp >= (toUnixTimestamp(now()) - {_LOG_WINDOW_S}) * 1000000000
    """
    metric_sql = f"""
        SELECT toUnixTimestamp(now()) - toUnixTimestamp(toDateTime(max(unix_milli) / 1000)) AS lag_s
        FROM signoz_metrics.distributed_samples_v4
        WHERE unix_milli >= (toUnixTimestamp(now()) - {_METRIC_WINDOW_S}) * 1000
    """

    # Distinguish "query failed" (None rows) from "no data in window" (empty/null
    # -> stale beyond the window). For staleness we must treat empty-in-window as
    # a large lag, otherwise a multi-hour wedge reads as "unknown" and we never act.
    log_rows = _clickhouse_query(log_sql)
    if log_rows is None:
        log_lag: int | None = None
    elif not log_rows or log_rows[0].get("lag_s") is None:
        log_lag = _LOG_WINDOW_S  # nothing for 4h -> definitely stale
    else:
        log_lag = int(float(log_rows[0]["lag_s"]))

    metric_rows = _clickhouse_query(metric_sql)
    if metric_rows is None:
        metric_lag: int | None = None
    elif not metric_rows or metric_rows[0].get("lag_s") is None:
        metric_lag = _METRIC_WINDOW_S  # nothing for 1h -> stale
    else:
        metric_lag = int(float(metric_rows[0]["lag_s"]))

    return Freshness(log_lag_s=log_lag, metric_lag_s=metric_lag)


def _check_guardrails(redis) -> tuple[bool, str]:
    """Return (can_restart, reason). Fail-open if Redis is unavailable."""
    if redis is None:
        return True, "no redis — guardrails disabled"
    now = int(time.time())
    try:
        last = redis.get(_REDIS_LAST_RESTART)
        if last is not None:
            gap = now - int(last)
            if gap < MIN_RESTART_GAP_MIN * 60:
                return False, f"last restart {gap // 60}m ago < {MIN_RESTART_GAP_MIN}m min gap"
        day_key = _REDIS_DAY_PREFIX + time.strftime("%Y-%m-%d", time.gmtime(now))
        count = int(redis.get(day_key) or 0)
        if count >= MAX_RESTARTS_PER_DAY:
            return False, f"{count} restarts today >= cap {MAX_RESTARTS_PER_DAY}"
    except Exception as e:  # noqa: BLE001 — never let guardrail bookkeeping block recovery
        logger.warning("watchdog guardrail check failed (%s) — allowing restart", e)
        return True, "guardrail check error — allowing"
    return True, "ok"


def _record_restart(redis) -> None:
    if redis is None:
        return
    now = int(time.time())
    try:
        redis.set(_REDIS_LAST_RESTART, now)
        day_key = _REDIS_DAY_PREFIX + time.strftime("%Y-%m-%d", time.gmtime(now))
        redis.incr(day_key)
        redis.expire(day_key, 2 * 86400)
    except Exception as e:  # noqa: BLE001
        logger.warning("watchdog failed to record restart in redis: %s", e)


def _restart_collector() -> None:
    """Restart the collector via the Docker Engine API over the unix socket."""
    transport = httpx.HTTPTransport(uds=DOCKER_SOCK)
    with httpx.Client(transport=transport, base_url="http://docker", timeout=60.0) as client:
        resp = client.post(f"/v1.43/containers/{COLLECTOR_CONTAINER}/restart", params={"t": 10})
        resp.raise_for_status()


@dataclass
class WatchdogResult:
    decision: Decision
    alert_message: str | None


def evaluate_and_act() -> WatchdogResult:
    """Synchronous core: measure, decide, and (if warranted) restart.

    Returns a WatchdogResult; the async wrapper sends any alert_message.
    """
    from agent.scheduler import _get_redis_client

    fresh = _measure_freshness()
    redis = _get_redis_client()
    can_restart, guard_reason = _check_guardrails(redis)
    decision = decide(
        fresh,
        log_stale_s=LOG_STALE_MIN * 60,
        metric_fresh_s=METRIC_FRESH_MIN * 60,
        can_restart=can_restart,
    )
    logger.info(
        "watchdog: action=%s log_lag=%s metric_lag=%s — %s",
        decision.action, fresh.log_lag_s, fresh.metric_lag_s, decision.reason,
    )

    if decision.action in ("ok", "skip"):
        return WatchdogResult(decision, None)

    if decision.action == "restart":
        try:
            _restart_collector()
        except Exception as e:  # noqa: BLE001
            logger.error("watchdog restart of %s FAILED: %s", COLLECTOR_CONTAINER, e)
            return WatchdogResult(
                decision,
                f"🔴 *First Light — ingestion watchdog*\n"
                f"Detected log-pipeline wedge but the auto-restart FAILED: `{e}`\n"
                f"{decision.reason}\nManual `docker restart {COLLECTOR_CONTAINER}` needed.",
            )
        _record_restart(redis)
        msg = (
            f"🔧 *First Light — ingestion watchdog*\n"
            f"Auto-restarted `{COLLECTOR_CONTAINER}` — {decision.reason}.\n"
            f"Log ingestion had stalled while metrics kept flowing (collector log "
            f"pipeline wedge)."
        )
        return WatchdogResult(decision, msg)

    # alert_only
    msg = (
        f"⚠️ *First Light — ingestion watchdog*\n{decision.reason}.\n"
        f"(guardrail: {guard_reason})"
    )
    return WatchdogResult(decision, msg)


async def run_ingestion_watchdog() -> None:
    """Scheduler entrypoint: runs the sync core off-loop, then sends any alert."""
    import asyncio

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, evaluate_and_act)
    except Exception as e:  # noqa: BLE001 — a watchdog must never crash the scheduler
        logger.error("watchdog evaluate_and_act crashed: %s", e)
        return

    if result.alert_message:
        try:
            from agent.notifications import broadcast_alert
            await broadcast_alert(result.alert_message)
        except Exception as e:  # noqa: BLE001
            logger.error("watchdog failed to send alert: %s", e)
