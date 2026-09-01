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

ALERT_REPEAT_AFTER_S = int(os.getenv("WATCHDOG_ALERT_REPEAT_AFTER_S", str(6 * 3600)))

_REDIS_LAST_RESTART = "watchdog:last_restart_ts"
_REDIS_LAST_ALERT_ACTION = "watchdog:last_alert_action"
_REDIS_LAST_ALERT_TS = "watchdog:last_alert_ts"
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
    - logs stale                 -> restart, whatever the metrics say, or
                                    alert_only if a guardrail blocks it
    """
    if fresh.log_lag_s is None:
        return Decision("skip", "log freshness unknown (ClickHouse unreachable)")

    if fresh.log_lag_s < log_stale_s:
        return Decision("ok", f"logs fresh ({fresh.log_lag_s}s lag)")

    # Reaching here means the log query SUCCEEDED (log_lag_s is not None), so
    # ClickHouse is reachable and the collector is the prime suspect either way.
    # Metric lag now only tells us which failure this looks like — it is not a
    # veto. The old code returned alert_only when both were stale, on the
    # assumption that meant a broader outage a restart could not fix. The
    # 2026-08-21 incident disproved that: the collector lost a startup race
    # against ClickHouse, failed to build ANY pipeline, and killed both signals
    # at once. A restart was the whole fix, and the watchdog sat on its hands
    # for 11 days. The min-gap and daily-cap guardrails bound the risk of
    # restarting when it genuinely will not help.
    metrics_fresh = fresh.metric_lag_s is not None and fresh.metric_lag_s < metric_fresh_s
    if metrics_fresh:
        reason = (
            f"log-pipeline wedge: logs stale {fresh.log_lag_s}s while metrics fresh "
            f"{fresh.metric_lag_s}s"
        )
    else:
        metric_desc = "unknown" if fresh.metric_lag_s is None else f"{fresh.metric_lag_s}s"
        reason = (
            f"collector not delivering: logs stale {fresh.log_lag_s}s and metrics "
            f"{metric_desc} — ClickHouse answered, so the collector is the suspect"
        )
    if not can_restart:
        return Decision("alert_only", reason + " — restart suppressed by guardrail")
    return Decision("restart", reason)


# --- Pure helpers -----------------------------------------------------------

def lag_from_rows(rows: list[dict] | None, window_s: int) -> int | None:
    """Turn a freshness query result into a lag in seconds.

    Three distinct outcomes, and conflating them is what hid the 2026-08-21
    outage for 11 days:

    - `rows is None`      -> the query FAILED; lag is unknown, don't act blind.
    - no rows / NULL lag  -> nothing in the window; stale by at least `window_s`.
    - a row with a value  -> the real lag.

    The trap: ClickHouse `max()` over an EMPTY set of a *non-nullable* column
    returns **0, not NULL**, so `lag = now - 0` came back as ~1.79e9 seconds
    (56 years) and sailed past the `is None` guard. Any lag larger than the
    query's own window is impossible by construction — the WHERE clause bounds
    it — so it can only be that artifact. Clamp it.
    """
    if rows is None:
        return None
    if not rows or rows[0].get("lag_s") is None:
        return window_s
    lag = int(float(rows[0]["lag_s"]))
    if lag < 0:
        return 0  # clock skew from a source running ahead
    return min(lag, window_s)


def should_alert(
    action: str,
    last_action: str | None,
    seconds_since_last: int | None,
    repeat_after_s: int,
) -> bool:
    """Decide whether this tick's outcome is worth notifying a human about.

    The watchdog ticks every 10 minutes. Re-sending an identical alert on every
    tick sent ~1,500 Pushover and ~1,500 Slack messages during the Aug 21
    outage, which is how a real alert becomes background noise. Notify on a
    *change* of state, or once per `repeat_after_s` while a problem persists.
    """
    healthy = action in ("ok", "skip")
    if healthy:
        # Exactly one "recovered" message, and only if we'd alerted before.
        return last_action is not None and last_action not in ("ok", "skip")
    if last_action != action:
        return True
    if seconds_since_last is None:
        return True
    return seconds_since_last >= repeat_after_s


# --- I/O helpers ------------------------------------------------------------

def _measure_freshness() -> Freshness:
    """Query ClickHouse for log + metric lag in seconds."""
    from agent.tools.infra_health import _clickhouse_query

    # `timestamp <= now` excludes clock-skewed sources that emit future-dated
    # logs (observed: a device sending timestamps ~5h ahead). Without this,
    # max(timestamp) is always in the future -> negative lag -> watchdog never
    # detects a real stall.
    log_sql = f"""
        SELECT toUnixTimestamp(now()) - intDiv(max(timestamp), 1000000000) AS lag_s
        FROM signoz_logs.distributed_logs_v2
        WHERE timestamp >= (toUnixTimestamp(now()) - {_LOG_WINDOW_S}) * 1000000000
          AND timestamp <= toUnixTimestamp64Nano(now64())
    """
    metric_sql = f"""
        SELECT toUnixTimestamp(now()) - intDiv(max(unix_milli), 1000) AS lag_s
        FROM signoz_metrics.distributed_samples_v4
        WHERE unix_milli >= (toUnixTimestamp(now()) - {_METRIC_WINDOW_S}) * 1000
          AND unix_milli <= toUnixTimestamp(now()) * 1000
    """

    return Freshness(
        log_lag_s=lag_from_rows(_clickhouse_query(log_sql), _LOG_WINDOW_S),
        metric_lag_s=lag_from_rows(_clickhouse_query(metric_sql), _METRIC_WINDOW_S),
    )


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


def _read_alert_state(redis) -> tuple[str | None, int | None]:
    """Return (last_alerted_action, seconds_since_that_alert)."""
    if redis is None:
        return None, None
    try:
        raw = redis.get(_REDIS_LAST_ALERT_ACTION)
        if raw is None:
            return None, None
        last_action = raw.decode() if isinstance(raw, bytes) else str(raw)
        ts = redis.get(_REDIS_LAST_ALERT_TS)
        elapsed = int(time.time()) - int(ts) if ts is not None else None
        return last_action, elapsed
    except Exception as e:  # noqa: BLE001 — never let bookkeeping suppress an alert
        logger.warning("watchdog could not read alert state (%s) — alerting", e)
        return None, None


def _record_alert(redis, action: str) -> None:
    if redis is None:
        return
    try:
        redis.set(_REDIS_LAST_ALERT_ACTION, action)
        redis.set(_REDIS_LAST_ALERT_TS, int(time.time()))
    except Exception as e:  # noqa: BLE001
        logger.warning("watchdog failed to record alert state: %s", e)


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

    # Every outcome below is gated by should_alert() so a persistent problem
    # notifies on state change and then at most once per ALERT_REPEAT_AFTER_S,
    # instead of every single tick.
    last_action, since_last = _read_alert_state(redis)

    def _gate(action: str) -> bool:
        return should_alert(action, last_action, since_last, ALERT_REPEAT_AFTER_S)

    if decision.action in ("ok", "skip"):
        if not _gate(decision.action):
            return WatchdogResult(decision, None)
        _record_alert(redis, decision.action)
        return WatchdogResult(
            decision,
            f"✅ *First Light — ingestion watchdog*\n"
            f"Ingestion has recovered — {decision.reason}.",
        )

    if decision.action == "restart":
        try:
            _restart_collector()
        except Exception as e:  # noqa: BLE001
            logger.error("watchdog restart of %s FAILED: %s", COLLECTOR_CONTAINER, e)
            _record_alert(redis, "restart_failed")
            return WatchdogResult(
                decision,
                f"🔴 *First Light — ingestion watchdog*\n"
                f"Ingestion has stalled but the auto-restart FAILED: `{e}`\n"
                f"{decision.reason}\nManual `docker restart {COLLECTOR_CONTAINER}` needed.",
            )
        _record_restart(redis)
        _record_alert(redis, decision.action)
        msg = (
            f"🔧 *First Light — ingestion watchdog*\n"
            f"Auto-restarted `{COLLECTOR_CONTAINER}` — {decision.reason}."
        )
        return WatchdogResult(decision, msg)

    # alert_only — a restart was warranted but a guardrail blocked it.
    if not _gate(decision.action):
        logger.info(
            "watchdog: alert suppressed (repeat of %s, last sent %ss ago, repeat after %ss)",
            last_action, since_last, ALERT_REPEAT_AFTER_S,
        )
        return WatchdogResult(decision, None)
    _record_alert(redis, decision.action)
    msg = (
        f"⚠️ *First Light — ingestion watchdog*\n{decision.reason}.\n"
        f"Auto-restart was NOT attempted — guardrail: {guard_reason}.\n"
        f"If this persists, check `docker logs {COLLECTOR_CONTAINER}` for pipeline "
        f"build errors."
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
