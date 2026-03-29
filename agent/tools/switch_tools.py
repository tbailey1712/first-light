"""
Switch and firewall interface stats from Telegraf SNMP data in ClickHouse.

Covers:
  - TP-Link TL-SG2424 switch (device: switch.mcducklabs.com)
  - pfSense firewall interfaces (device: pfsense.mcducklabs.com)

Metrics are cumulative counters polled every 60s by Telegraf.
Delta (max - min) over the query window gives bytes/errors in that period.
"""

import json
import logging
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)

_SWITCH_DEVICE = "switch.mcducklabs.com"
_PFSENSE_DEVICE = "pfsense.mcducklabs.com"
# Skip virtual/management interfaces that are never interesting
_SKIP_PORTS = {"AUX", "Loopback", "lo", "lo0"}


def _clickhouse_url() -> str:
    cfg = get_config()
    return f"http://{cfg.signoz_clickhouse_host}:8123"


def _run_query(sql: str) -> list[dict]:
    cfg = get_config()
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                _clickhouse_url(),
                params={
                    "user": cfg.signoz_clickhouse_user,
                    "password": cfg.signoz_clickhouse_password,
                    "query": sql,
                    "default_format": "JSONEachRow",
                },
            )
        if resp.status_code != 200:
            return [{"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}]
        rows = []
        for line in resp.text.strip().splitlines():
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return rows
    except Exception as e:
        return [{"error": str(e)}]


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _port_traffic_query(device: str, hours: int) -> str:
    return f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'name') AS port,
            (maxIf(s.value, s.metric_name = 'interface_in_octets')
             - minIf(s.value, s.metric_name = 'interface_in_octets')) AS bytes_in,
            (maxIf(s.value, s.metric_name = 'interface_out_octets')
             - minIf(s.value, s.metric_name = 'interface_out_octets')) AS bytes_out
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name IN ('interface_in_octets', 'interface_out_octets')
          AND simpleJSONExtractString(ts.labels, 'device') = '{device}'
          AND s.unix_milli > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000
        GROUP BY port
        HAVING (bytes_in + bytes_out) > 0
        ORDER BY (bytes_in + bytes_out) DESC
    """


def _port_errors_query(device: str, hours: int) -> str:
    return f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'name') AS port,
            (maxIf(s.value, s.metric_name = 'interface_in_errors')
             - minIf(s.value, s.metric_name = 'interface_in_errors')) AS in_errors,
            (maxIf(s.value, s.metric_name = 'interface_out_errors')
             - minIf(s.value, s.metric_name = 'interface_out_errors')) AS out_errors,
            (maxIf(s.value, s.metric_name = 'interface_in_discards')
             - minIf(s.value, s.metric_name = 'interface_in_discards')) AS in_discards,
            (maxIf(s.value, s.metric_name = 'interface_out_discards')
             - minIf(s.value, s.metric_name = 'interface_out_discards')) AS out_discards
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name IN (
            'interface_in_errors', 'interface_out_errors',
            'interface_in_discards', 'interface_out_discards'
        )
          AND simpleJSONExtractString(ts.labels, 'device') = '{device}'
          AND s.unix_milli > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000
        GROUP BY port
        HAVING (in_errors + out_errors + in_discards + out_discards) > 0
        ORDER BY (in_errors + out_errors) DESC
    """


@tool
def query_switch_port_traffic(hours: int = 24) -> str:
    """Get traffic volume per switch port over the last N hours.

    Shows bytes in/out for each active port on the TP-Link TL-SG2424.
    Useful for identifying top-traffic ports and bandwidth hogs.

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        JSON with port name, bytes_in, bytes_out, total for each active port.
    """
    rows = _run_query(_port_traffic_query(_SWITCH_DEVICE, hours))
    if rows and "error" in rows[0]:
        return json.dumps(rows[0])

    result = []
    for r in rows:
        port = r.get("port", "")
        if port in _SKIP_PORTS:
            continue
        bytes_in = float(r.get("bytes_in", 0))
        bytes_out = float(r.get("bytes_out", 0))
        result.append({
            "port": port,
            "bytes_in": _human_bytes(bytes_in),
            "bytes_out": _human_bytes(bytes_out),
            "total": _human_bytes(bytes_in + bytes_out),
        })

    if not result:
        return json.dumps({"status": "no traffic data", "hours": hours})
    return json.dumps({"switch": _SWITCH_DEVICE, "hours": hours, "ports": result}, indent=2)


@tool
def query_switch_port_errors(hours: int = 24) -> str:
    """Get error and discard counts per switch port over the last N hours.

    Ports with non-zero errors may indicate bad cables, duplex mismatches,
    or overloaded links. Any errors > 0 are worth investigating.

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        JSON with ports that have errors or discards, or a clean-bill-of-health message.
    """
    rows = _run_query(_port_errors_query(_SWITCH_DEVICE, hours))
    if rows and "error" in rows[0]:
        return json.dumps(rows[0])

    result = []
    for r in rows:
        port = r.get("port", "")
        if port in _SKIP_PORTS:
            continue
        result.append({
            "port": port,
            "in_errors": int(float(r.get("in_errors", 0))),
            "out_errors": int(float(r.get("out_errors", 0))),
            "in_discards": int(float(r.get("in_discards", 0))),
            "out_discards": int(float(r.get("out_discards", 0))),
        })

    if not result:
        return json.dumps({"status": "clean", "message": "No switch port errors or discards in the last {hours}h"})
    return json.dumps({"switch": _SWITCH_DEVICE, "hours": hours, "ports_with_errors": result}, indent=2)


@tool
def query_pfsense_interface_traffic(hours: int = 24) -> str:
    """Get traffic volume per pfSense firewall interface over the last N hours.

    Shows bytes in/out for WAN, LAN, and VLAN interfaces on pfSense.
    Useful for monitoring WAN utilization and inter-VLAN traffic.

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        JSON with interface name, bytes_in, bytes_out for each active interface.
    """
    rows = _run_query(_port_traffic_query(_PFSENSE_DEVICE, hours))
    if rows and "error" in rows[0]:
        return json.dumps(rows[0])

    result = []
    for r in rows:
        port = r.get("port", "")
        if port in _SKIP_PORTS:
            continue
        bytes_in = float(r.get("bytes_in", 0))
        bytes_out = float(r.get("bytes_out", 0))
        result.append({
            "interface": port,
            "bytes_in": _human_bytes(bytes_in),
            "bytes_out": _human_bytes(bytes_out),
            "total": _human_bytes(bytes_in + bytes_out),
        })

    if not result:
        return json.dumps({"status": "no traffic data", "hours": hours})
    return json.dumps({"device": _PFSENSE_DEVICE, "hours": hours, "interfaces": result}, indent=2)
