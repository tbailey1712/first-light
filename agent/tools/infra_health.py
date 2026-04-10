"""
Reporting infrastructure health check.

Detects stale or missing data from each collector/exporter in the First Light
pipeline. Called at the start of the daily report so data gaps are surfaced
before domain agents run and produce findings based on incomplete data.

Checks:
  - Metric freshness per collector (ClickHouse max(unix_milli) vs now)
  - Log ingestion freshness (last syslog entry in signoz_logs)
  - ntopng API reachability
  - Key fl-* Docker container statuses via the Docker socket
"""

import json
import logging
import time
from typing import Optional

import httpx

from agent.config import get_config

logger = logging.getLogger(__name__)

# ── Collector definitions ────────────────────────────────────────────────────
# Each entry: (name, sample_metric, warn_minutes, critical_minutes, description)
_METRIC_COLLECTORS = [
    ("adguard-exporter",   "adguard_queries_total",        90,  360,  "AdGuard DNS analytics (runs on adguard LXC)"),
    ("telegraf-snmp",      "interface_in_octets",          90,  360,  "Switch + pfSense SNMP via Telegraf"),
    ("proxmox-exporter",   "pve_node_cpu_usage_ratio",     90,  360,  "Proxmox PVE metrics"),
    ("qnap-exporter",      "qnap_cpu_usage_percent",       90,  360,  "QNAP NAS metrics"),
    ("validator-metrics",  "beacon_active_validators",     90,  360,  "Nimbus beacon node metrics"),
]

# Threshold for log ingestion staleness
_LOG_WARN_MINUTES  = 30
_LOG_CRIT_MINUTES  = 120

# fl-* containers that must be running
_REQUIRED_CONTAINERS = [
    "fl-agent",
    "fl-slack-bot",
    "fl-redis",
    "fl-threat-intel-enricher",
    "fl-proxmox-exporter",
    "fl-qnap-snmp-exporter",
    "fl-qnap-api-exporter",
    "fl-telegraf-snmp",
    "fl-crowdsec",
    "fl-rsyslog",
    "fl-mcp",
]


def _clickhouse_query(sql: str) -> list[dict] | None:
    """Run a ClickHouse query. Returns row list, empty list if no rows, or None on error/timeout."""
    cfg = get_config()
    url = f"http://{cfg.signoz_clickhouse_host}:8123"
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(url, params={
                "user": cfg.signoz_clickhouse_user,
                "password": cfg.signoz_clickhouse_password,
                "query": sql,
                "default_format": "JSONEachRow",
                "max_execution_time": 12,
            })
        if resp.status_code != 200:
            logger.error("ClickHouse query failed: HTTP %s", resp.status_code)
            return None
        rows = []
        for line in resp.text.strip().splitlines():
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return rows
    except httpx.TimeoutException:
        logger.error("ClickHouse query failed: timed out")
        return None
    except Exception as e:
        logger.error("ClickHouse query failed: %s", e)
        return None


def _check_metric_staleness() -> list[dict]:
    """Return a health entry per collector based on metric timestamp."""
    metrics = [m for _, m, _, _, _ in _METRIC_COLLECTORS]
    placeholders = ", ".join(f"'{m}'" for m in metrics)
    sql = f"""
        SELECT
            metric_name,
            toUnixTimestamp(toDateTime(max(unix_milli) / 1000)) AS last_ts
        FROM signoz_metrics.distributed_samples_v4
        WHERE metric_name IN ({placeholders})
        GROUP BY metric_name
    """
    rows = _clickhouse_query(sql)
    if rows is None:
        return [{
            "collector": name, "status": "warning", "metric": metric,
            "last_seen": None, "minutes_ago": None, "description": desc,
            "detail": "Metric staleness check timed out — ClickHouse under load",
        } for name, metric, _, _, desc in _METRIC_COLLECTORS]
    last_by_metric = {r["metric_name"]: int(float(r["last_ts"])) for r in rows}

    now = int(time.time())
    results = []
    for name, metric, warn_min, crit_min, desc in _METRIC_COLLECTORS:
        last_ts = last_by_metric.get(metric)
        if last_ts is None:
            results.append({
                "collector": name,
                "status": "critical",
                "metric": metric,
                "last_seen": None,
                "minutes_ago": None,
                "description": desc,
                "detail": f"No data ever received — collector may never have started",
            })
            continue

        minutes_ago = (now - last_ts) // 60
        if minutes_ago >= crit_min:
            status = "critical"
        elif minutes_ago >= warn_min:
            status = "warning"
        else:
            status = "ok"

        results.append({
            "collector": name,
            "status": status,
            "metric": metric,
            "last_seen": last_ts,
            "minutes_ago": minutes_ago,
            "description": desc,
            "detail": f"Last data {minutes_ago}m ago" if status != "ok" else f"Current ({minutes_ago}m ago)",
        })

    return results


def _check_log_ingestion() -> dict:
    """Check how recently a syslog entry arrived in signoz_logs."""
    sql = """
        SELECT toUnixTimestamp(toDateTime(max(timestamp) / 1000000000)) AS last_ts
        FROM signoz_logs.distributed_logs_v2
        WHERE resources_string['host.name'] != ''
    """
    rows = _clickhouse_query(sql)
    now = int(time.time())

    if rows is None:
        # Query failed or timed out — ClickHouse under load, not a syslog outage
        return {
            "collector": "syslog-ingestion",
            "status": "warning",
            "minutes_ago": None,
            "detail": "Log ingestion check timed out — ClickHouse under load, syslog status unknown",
        }

    if not rows or rows[0].get("last_ts") is None:
        return {
            "collector": "syslog-ingestion",
            "status": "critical",
            "minutes_ago": None,
            "detail": "No syslog entries found in signoz_logs — OTel collector may be down",
        }

    last_ts = int(float(rows[0]["last_ts"]))
    minutes_ago = (now - last_ts) // 60

    if minutes_ago >= _LOG_CRIT_MINUTES:
        status = "critical"
    elif minutes_ago >= _LOG_WARN_MINUTES:
        status = "warning"
    else:
        status = "ok"

    return {
        "collector": "syslog-ingestion",
        "status": status,
        "minutes_ago": minutes_ago,
        "detail": f"Last log entry {minutes_ago}m ago",
    }


def _check_containers() -> list[dict]:
    """Check fl-* container statuses via Docker socket."""
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds="/var/run/docker.sock"), timeout=5.0) as client:
            resp = client.get("http://docker/containers/json?all=true")
        containers = resp.json()
    except Exception as e:
        return [{
            "collector": "docker-socket",
            "status": "warning",
            "detail": f"Could not reach Docker socket: {e}",
        }]

    running = {c["Names"][0].lstrip("/") for c in containers if c["State"] == "running"}
    results = []
    for name in _REQUIRED_CONTAINERS:
        if name in running:
            results.append({"container": name, "status": "ok"})
        else:
            # Check if it exists at all
            all_names = {c["Names"][0].lstrip("/") for c in containers}
            if name in all_names:
                state = next((c["State"] for c in containers if c["Names"][0].lstrip("/") == name), "unknown")
                results.append({
                    "container": name,
                    "status": "critical",
                    "detail": f"Container exists but state='{state}' (not running)",
                })
            else:
                results.append({
                    "container": name,
                    "status": "warning",
                    "detail": "Container not found",
                })
    return results


def _check_ntopng() -> dict:
    """Check ntopng API reachability."""
    cfg = get_config()
    if not cfg.ntopng_host:
        return {"collector": "ntopng", "status": "warning", "detail": "Not configured"}
    try:
        with httpx.Client(timeout=5.0, follow_redirects=True) as client:
            resp = client.post(
                f"http://{cfg.ntopng_host}:{cfg.ntopng_port}/authorize.html",
                data={"user": cfg.ntopng_username, "password": cfg.ntopng_password},
            )
        if resp.status_code in (200, 302):
            return {"collector": "ntopng", "status": "ok", "detail": "Reachable"}
        return {"collector": "ntopng", "status": "warning", "detail": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"collector": "ntopng", "status": "critical", "detail": f"Unreachable: {e}"}


def query_reporting_infra_health() -> str:
    """Check health of all First Light data collection infrastructure.

    Detects stale metrics, log ingestion gaps, down containers, and unreachable
    APIs. Should be called at the start of every daily report so data gaps are
    flagged before domain agents produce findings based on incomplete data.

    Returns:
        JSON with per-collector status (ok/warning/critical), staleness in minutes,
        container statuses, and an overall health summary.
    """
    metric_checks = _check_metric_staleness()
    log_check = _check_log_ingestion()
    container_checks = _check_containers()
    ntopng_check = _check_ntopng()

    # Roll up overall severity
    all_statuses = (
        [c["status"] for c in metric_checks]
        + [log_check["status"]]
        + [c["status"] for c in container_checks]
        + [ntopng_check["status"]]
    )
    if "critical" in all_statuses:
        overall = "critical"
    elif "warning" in all_statuses:
        overall = "warning"
    else:
        overall = "ok"

    critical_items = [
        c.get("collector") or c.get("container")
        for c in metric_checks + container_checks + [log_check, ntopng_check]
        if c.get("status") == "critical"
    ]
    warning_items = [
        c.get("collector") or c.get("container")
        for c in metric_checks + container_checks + [log_check, ntopng_check]
        if c.get("status") == "warning"
    ]

    return json.dumps({
        "overall": overall,
        "critical": critical_items,
        "warning": warning_items,
        "metric_collectors": metric_checks,
        "log_ingestion": log_check,
        "containers": container_checks,
        "ntopng": ntopng_check,
        "note": (
            "Any critical item means domain agent findings may be based on incomplete data. "
            "Flag infrastructure failures prominently — before reporting on findings."
        ),
    }, indent=2)


# Also export as a langchain tool for agent use
from langchain_core.tools import tool as _tool
query_reporting_infra_health = _tool(query_reporting_infra_health)
