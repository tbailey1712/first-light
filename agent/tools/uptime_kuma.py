"""
Uptime Kuma tools — queries kuma.db directly via Python's sqlite3.

The kuma.db volume is mounted read-only at /data/uptimekuma/kuma.db.
"""

import json
import sqlite3
from datetime import datetime, timezone

from langchain_core.tools import tool

DB_PATH = "/data/uptimekuma/kuma.db"


def _connect():
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


@tool
def query_uptime_kuma_status() -> str:
    """Get current up/down status and response time for all Uptime Kuma monitors.

    Returns:
        JSON list of monitors with name, type, status, ping_ms, and last_checked.
    """
    sql = """
        SELECT
            m.id,
            m.name,
            m.type,
            m.url,
            m.active,
            h.status,
            h.ping,
            h.msg,
            h.time AS last_checked
        FROM monitor m
        LEFT JOIN heartbeat h ON h.id = (
            SELECT id FROM heartbeat WHERE monitor_id = m.id ORDER BY time DESC LIMIT 1
        )
        ORDER BY m.name
    """
    try:
        with _connect() as conn:
            rows = [dict(r) for r in conn.execute(sql)]
        for r in rows:
            r["status_text"] = "up" if r["status"] == 1 else ("down" if r["status"] == 0 else "unknown")
            r["active"] = bool(r["active"])
        return json.dumps(rows, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def query_uptime_kuma_uptime(days: int = 1) -> str:
    """Get uptime percentage for all monitors over the past N days.

    Args:
        days: Number of days to calculate uptime for (default: 1)

    Returns:
        JSON list of monitors with name, uptime_pct, avg_ping_ms, and check counts.
    """
    # stat_daily timestamp is unix epoch at day boundary (UTC midnight)
    sql = """
        SELECT
            m.name,
            SUM(s.up) AS up_count,
            SUM(s.down) AS down_count,
            ROUND(AVG(s.ping), 1) AS avg_ping_ms,
            ROUND(MIN(s.ping_min), 1) AS min_ping_ms,
            ROUND(MAX(s.ping_max), 1) AS max_ping_ms
        FROM monitor m
        JOIN stat_daily s ON s.monitor_id = m.id
        WHERE s.timestamp >= strftime('%s', 'now', ?)
        GROUP BY m.id, m.name
        ORDER BY m.name
    """
    interval = f"-{days} days"
    try:
        with _connect() as conn:
            rows = [dict(r) for r in conn.execute(sql, (interval,))]
        for r in rows:
            total = (r["up_count"] or 0) + (r["down_count"] or 0)
            r["uptime_pct"] = round(r["up_count"] / total * 100, 2) if total > 0 else None
        return json.dumps(rows, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def query_uptime_kuma_incidents(hours: int = 24) -> str:
    """Get recent downtime incidents across all monitors.

    Args:
        hours: Lookback window in hours (default: 24)

    Returns:
        JSON list of down events with monitor name, time, duration, and error message.
    """
    sql = """
        SELECT
            m.name,
            h.time AS down_at,
            h.end_time AS recovered_at,
            h.duration AS duration_seconds,
            h.msg AS error,
            h.down_count
        FROM heartbeat h
        JOIN monitor m ON m.id = h.monitor_id
        WHERE h.status = 0
          AND h.time >= datetime('now', ?)
        ORDER BY h.time DESC
    """
    interval = f"-{hours} hours"
    try:
        with _connect() as conn:
            rows = [dict(r) for r in conn.execute(sql, (interval,))]
        return json.dumps(rows, indent=2) if rows else json.dumps([])
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def query_uptime_kuma_monitors() -> str:
    """List all Uptime Kuma monitor definitions with URL, check interval, and config.

    Use this to correlate a failing monitor with what it's actually checking, or to
    verify a service is being monitored before flagging it as unmonitored.

    Returns:
        JSON with total count and a list of monitor definitions including id, name,
        type, url/hostname/port, interval, retry config, active state, upside_down
        flag, and notification channel count.
    """
    sql = """
        SELECT
            m.id,
            m.name,
            m.type,
            m.url,
            m.hostname,
            m.port,
            m.interval,
            m.retry_interval,
            m.max_retries,
            m.active,
            m.upside_down,
            COUNT(mn.monitor_id) AS notification_count
        FROM monitor m
        LEFT JOIN monitor_notification mn ON mn.monitor_id = m.id
        GROUP BY m.id
        ORDER BY m.name
    """
    try:
        with _connect() as conn:
            rows = [dict(r) for r in conn.execute(sql)]
        for r in rows:
            r["active"] = bool(r["active"])
            r["upside_down"] = bool(r["upside_down"])
        return json.dumps({"total": len(rows), "monitors": rows}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})
