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

# Authoritative port map — updated 2026-04-06
_PORT_LABELS: dict[str, str] = {
    "1":  "AP-2F-Back (unifi-2f-back) — TRUNK V1/V2/V3",
    "2":  "Floor1-Desk (Intel NUC fam-desk)",
    "3":  "MBR-Cabinet (Hue3 / LiftMaster / Airthings) — IoT V2",
    "4":  "Ellie-Bedroom (empty)",
    "5":  "Backyard-Camera 08:CC:81 via PoE-injector → Ethernet-over-COAX → 192.168.3.15 — CCTV V3",
    "6":  "Bsmt-Cabinet (empty) — IoT V2",
    "7":  "Office-Switch (printer + office devices)",
    "8":  "(available) — IoT V2",
    "9":  "QNAP-NAS TS-462 + containers — IoT V2",
    "10": "AP-1F-Front (unifi-1f-front) — TRUNK V1/V2/V3",
    "11": "Alex-Bedroom (empty)",
    "12": "(available) — IoT V2",
    "13": "vldtr ETH validator — DMZ V4",
    "14": "Smart-Meter Rainforest d8:d5:b9:00:bb:9f — IoT V2",
    "15": "Camera-Front Hikvision — CCTV V3",
    "16": "Heatpump-GW Resideo — IoT V2",
    "17": "Proxmox-V2-NIC Supermicro eth2 — IoT V2",
    "18": "Supermicro-IPMI BMC — trusted V1",
    "19": "Proxmox-V1-NIC Supermicro eth1 — trusted V1",
    "20": "Garage-Switch + 3 downstream cameras — TRUNK V1/V3",
    "21": "AP-Basement (unifi-basement) — TRUNK V1/V2/V3",
    "22": "Proxmox-V4-NIC Supermicro eth0 SFP — DMZ V4",
    "23": "Firewall pfSense 3100 SFP — TRUNK V1/V2/V3/V4",
    "24": "rpi-ntop Raspberry Pi 4 ntopng — trusted V1",
}


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
            "label": _PORT_LABELS.get(port, f"Port {port} (unknown device)"),
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
            "label": _PORT_LABELS.get(port, f"Port {port} (unknown device)"),
            "in_errors": int(float(r.get("in_errors", 0))),
            "out_errors": int(float(r.get("out_errors", 0))),
            "in_discards": int(float(r.get("in_discards", 0))),
            "out_discards": int(float(r.get("out_discards", 0))),
        })

    if not result:
        return json.dumps({"status": "clean", "message": f"No switch port errors or discards in the last {hours}h"})
    return json.dumps({"switch": _SWITCH_DEVICE, "hours": hours, "ports_with_errors": result}, indent=2)


@tool
def query_switch_port_status() -> str:
    """Get per-port operational status and link speed for the TP-Link TL-SG2424 switch.

    Queries ClickHouse for the latest ifOperStatus (up/down) and link speed (Mbps)
    per port, as collected by Telegraf SNMP polling.

    For VLAN traffic analysis, use query_ntopng_vlan_traffic.
    For cross-VLAN isolation verification, combine this tool with ntopng flow data
    (query_ntopng_vlan_traffic shows per-VLAN traffic from ntopng).

    Returns:
        JSON with switch device, per-port status/speed, and up/down summary counts.
        Falls back to activity-based status from traffic data if ifOperStatus is not
        collected by Telegraf (metric may not be configured in the SNMP plugin).
    """
    # Try ifOperStatus — may be collected as 'interface_operational_status' or 'ifOperStatus'
    status_sql = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'name') AS port,
            argMax(s.value, s.unix_milli) AS oper_status
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name IN ('interface_operational_status', 'ifOperStatus')
          AND simpleJSONExtractString(ts.labels, 'device') = '{_SWITCH_DEVICE}'
          AND s.unix_milli > toUnixTimestamp(now() - INTERVAL 1 HOUR) * 1000
        GROUP BY port
        ORDER BY port
    """

    speed_sql = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'name') AS port,
            argMax(s.value, s.unix_milli) AS speed_mbps
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name IN ('interface_speed', 'ifHighSpeed', 'ifSpeed')
          AND simpleJSONExtractString(ts.labels, 'device') = '{_SWITCH_DEVICE}'
          AND s.unix_milli > toUnixTimestamp(now() - INTERVAL 1 HOUR) * 1000
        GROUP BY port
        ORDER BY port
    """

    def _status_label(val: float) -> str:
        if val == 1:
            return "up"
        elif val == 2:
            return "down"
        return "unknown"

    status_rows = _run_query(status_sql)
    if status_rows and "error" in status_rows[0]:
        logger.warning("ifOperStatus query error: %s", status_rows[0]["error"])
        status_rows = []

    # Filter out empty port names and skip management interfaces
    status_rows = [r for r in status_rows if r.get("port") and r["port"] not in _SKIP_PORTS]

    if not status_rows:
        # Graceful fallback: derive "active" ports from recent traffic
        traffic_rows = _run_query(_port_traffic_query(_SWITCH_DEVICE, 1))
        active_ports = []
        if not (traffic_rows and "error" in traffic_rows[0]):
            for r in traffic_rows:
                port = r.get("port", "")
                if port and port not in _SKIP_PORTS:
                    active_ports.append(port)
        return json.dumps({
            "note": (
                "Port status metrics not available — Telegraf SNMP config may not collect "
                "ifOperStatus. Use query_switch_port_traffic for activity-based status."
            ),
            "active_ports": active_ports,
        }, indent=2)

    # Build speed lookup
    speed_rows = _run_query(speed_sql)
    speed_map: dict[str, float] = {}
    if speed_rows and "error" not in speed_rows[0]:
        for r in speed_rows:
            port = r.get("port", "")
            if port:
                raw = float(r.get("speed_mbps", 0))
                # ifSpeed is in bps; ifHighSpeed is already in Mbps
                # Heuristic: values > 1_000_000 are almost certainly bps
                speed_map[port] = raw / 1_000_000 if raw > 1_000_000 else raw

    ports = []
    up_count = 0
    down_count = 0
    for r in status_rows:
        port = r["port"]
        oper_val = float(r.get("oper_status", 0))
        status_str = _status_label(oper_val)
        speed = speed_map.get(port)
        entry: dict = {"port": port, "status": status_str}
        if speed is not None:
            entry["speed_mbps"] = int(speed) if speed == int(speed) else round(speed, 1)
        ports.append(entry)
        if status_str == "up":
            up_count += 1
        elif status_str == "down":
            down_count += 1

    return json.dumps({
        "switch": _SWITCH_DEVICE,
        "ports": ports,
        "summary": {
            "up": up_count,
            "down": down_count,
            "unknown": len(ports) - up_count - down_count,
            "total": len(ports),
        },
    }, indent=2)


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


@tool
def query_wan_bandwidth_daily(days: int = 7) -> str:
    """Get daily WAN internet bandwidth totals (download and upload) from pfSense.

    Uses rate-based delta calculation on pfSense mvneta2 (WAN) SNMP counters from
    Telegraf, correctly handling counter resets from reboots. Reports actual internet
    traffic only — not internal LAN traffic.

    Args:
        days: Number of past days to return (default: 7)

    Returns:
        JSON list of daily records with wan_download_gb, wan_upload_gb, wan_total_gb.
    """
    config = get_config()
    url = f"{config.signoz_clickhouse_url}/"
    query = f"""
        WITH ordered AS (
            SELECT
                toDate(toDateTime(unix_milli / 1000)) AS day,
                unix_milli,
                value,
                metric_name,
                lagInFrame(value) OVER (PARTITION BY metric_name ORDER BY unix_milli) AS prev_value
            FROM signoz_metrics.samples_v4 s
            JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
            WHERE ts.metric_name IN ('interface_in_octets', 'interface_out_octets')
              AND simpleJSONExtractString(ts.labels, 'instance') = '192.168.1.1'
              AND simpleJSONExtractString(ts.labels, 'name') = 'mvneta2'
              AND unix_milli >= (toUnixTimestamp(now() - INTERVAL {days} DAY)) * 1000
        )
        SELECT
            day,
            round(sumIf(value - prev_value,
                metric_name = 'interface_in_octets'
                AND value > prev_value AND prev_value > 0) / 1e9, 2) AS wan_download_gb,
            round(sumIf(value - prev_value,
                metric_name = 'interface_out_octets'
                AND value > prev_value AND prev_value > 0) / 1e9, 2) AS wan_upload_gb
        FROM ordered
        GROUP BY day
        ORDER BY day DESC
        FORMAT JSON
    """
    try:
        resp = httpx.post(url, content=query, timeout=30,
                          auth=(config.signoz_clickhouse_user, config.signoz_clickhouse_password))
        resp.raise_for_status()
        rows = resp.json().get("data", [])
        result = []
        for r in rows:
            down = float(r.get("wan_download_gb", 0))
            up = float(r.get("wan_upload_gb", 0))
            result.append({
                "date": r["day"],
                "wan_download_gb": round(down, 1),
                "wan_upload_gb": round(up, 1),
                "wan_total_gb": round(down + up, 1),
            })
        return json.dumps({"wan_bandwidth_daily": result}, indent=2)
    except Exception as e:
        logger.error(f"query_wan_bandwidth_daily failed: {e}")
        return json.dumps({"error": str(e)})


@tool
def query_switch_events(hours: int = 24) -> str:
    """Get switch syslog events: port link state changes and flapping detection.

    Queries ClickHouse for port up/down events from the TP-Link TL-SG2424 switch
    syslog. Detects flapping ports (more than 2 state changes in any 1-hour window),
    which can indicate bad cables, failing NICs, or STP instability.

    Each flapping port includes:
    - Human-readable label (device connected to that port)
    - Time-of-day bucketing (counts per hour) — helps diagnose dusk/dawn PoE issues
    - Interval stats (min/mean/max minutes between state changes)
    - Whether events cluster at dusk (17-21h) or dawn (5-8h)

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        JSON with per-port event timeline, state change counts, flapping flags,
        time-of-day analysis, interval stats, and an alerts list.
    """
    import re
    import statistics
    from collections import defaultdict
    from datetime import datetime, timedelta

    sql = f"""
        SELECT
            toDateTime(timestamp / 1000000000) AS ts,
            body
        FROM signoz_logs.logs_v2
        WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
          AND body LIKE '%192.168.1.2%'
          AND body LIKE '%changed state to%'
        ORDER BY ts ASC
        LIMIT 500
    """
    rows = _run_query(sql)
    if rows and "error" in rows[0]:
        return json.dumps(rows[0])

    port_events: dict = defaultdict(list)
    _port_re = re.compile(r'port\s+(\d+),\s+changed state to\s+(\w+)', re.IGNORECASE)

    for row in rows:
        body = row.get("body", "")
        ts = row.get("ts", "")
        m = _port_re.search(body)
        if m:
            port_num = m.group(1)
            state = m.group(2).lower()
            port_events[port_num].append({"ts": ts, "state": state})

    if not port_events:
        return json.dumps({
            "status": "no_events",
            "message": f"No switch port state change events in the last {hours}h",
            "hours": hours,
        })

    def _is_flapping(times: list[datetime]) -> bool:
        if len(times) <= 2:
            return False
        for t in times:
            count = sum(1 for t2 in times if abs((t2 - t).total_seconds()) <= 3600)
            if count > 2:
                return True
        return False

    def _parse_times(events: list) -> list[datetime]:
        out = []
        for e in events:
            try:
                out.append(datetime.fromisoformat(e["ts"]))
            except Exception:
                pass
        return out

    def _interval_stats(times: list[datetime]) -> dict | None:
        if len(times) < 2:
            return None
        gaps = [(times[i+1] - times[i]).total_seconds() / 60 for i in range(len(times) - 1)]
        return {
            "min_minutes": round(min(gaps), 1),
            "mean_minutes": round(statistics.mean(gaps), 1),
            "max_minutes": round(max(gaps), 1),
        }

    def _tod_analysis(times: list[datetime]) -> dict:
        """Bucket events by hour of day and flag dusk/dawn clustering."""
        buckets: dict[int, int] = defaultdict(int)
        for t in times:
            buckets[t.hour] += 1
        total = len(times)
        dusk_count = sum(buckets[h] for h in range(17, 22))   # 17:00–21:59
        dawn_count = sum(buckets[h] for h in range(5, 9))     # 05:00–08:59
        result: dict = {
            "by_hour": {str(h): buckets[h] for h in sorted(buckets)},
        }
        if dusk_count / total >= 0.5:
            result["pattern"] = f"dusk-clustered ({dusk_count}/{total} events between 17:00-22:00) — possible IR-LED PoE surge"
        elif dawn_count / total >= 0.5:
            result["pattern"] = f"dawn-clustered ({dawn_count}/{total} events between 05:00-09:00) — possible IR-LED PoE surge"
        else:
            result["pattern"] = "no clear time-of-day clustering"
        return result

    ports_summary = []
    alerts = []

    for port_num, events in sorted(port_events.items(), key=lambda x: int(x[0])):
        times = _parse_times(events)
        flapping = _is_flapping(times) if times else len(events) > 4
        changes = len(events)

        entry: dict = {
            "port": port_num,
            "label": _PORT_LABELS.get(port_num, f"Port {port_num}"),
            "state_changes": changes,
            "flapping": flapping,
            "current_state": events[-1]["state"] if events else "unknown",
            "last_change": events[-1]["ts"] if events else None,
            "events": events,
        }

        if times:
            entry["interval_stats"] = _interval_stats(times)
            if changes >= 3:
                entry["time_of_day_analysis"] = _tod_analysis(times)

        ports_summary.append(entry)

        label = _PORT_LABELS.get(port_num, f"Port {port_num}")
        if flapping:
            alerts.append(
                f"Port {port_num} ({label}) FLAPPING — {changes} state changes in {hours}h "
                f"(last: {events[-1]['state']} at {events[-1]['ts']})"
            )
        elif changes > 1:
            alerts.append(
                f"Port {port_num} ({label}) changed state {changes}x in {hours}h "
                f"(last: {events[-1]['state']} at {events[-1]['ts']})"
            )

    return json.dumps({
        "switch": _SWITCH_DEVICE,
        "hours": hours,
        "ports_with_events": ports_summary,
        "alerts": alerts,
        "total_events": sum(len(e) for e in port_events.values()),
    }, indent=2)
