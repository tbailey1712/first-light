"""
QNAP NAS health tools.

query_qnap_health: queries the fl-qnap-api-exporter Prometheus endpoint.
query_qnap_events: queries ClickHouse for QNAP syslog events (security, login, warnings).
query_qnap_directory_sizes: uses the QNAP File Station API for directory analysis.
"""

import hashlib
import json
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import httpx
from langchain_core.tools import tool

from agent.config import get_config

# Module-level session cache — reuse QNAP auth token for up to 50 minutes
_qnap_sid: Optional[str] = None
_qnap_sid_expiry: float = 0.0
_qnap_sid_lock = threading.Lock()


def _parse_prometheus(text: str) -> Dict[str, List[Tuple[Dict, float]]]:
    """Parse Prometheus text format into {metric: [(labels, value), ...]}."""
    result: Dict[str, List[Tuple[Dict, float]]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+([\d.eE+\-]+)', line)
        if m:
            name, labels_str, val = m.group(1), m.group(2), m.group(3)
            labels = dict(re.findall(r'(\w+)="([^"]*)"', labels_str))
        else:
            m = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\s+([\d.eE+\-]+)', line)
            if not m:
                continue
            name, val, labels = m.group(1), m.group(2), {}
        try:
            result.setdefault(name, []).append((labels, float(val)))
        except ValueError:
            pass
    return result


def _first(metrics, name, labels_filter=None):
    for labels, val in metrics.get(name, []):
        if labels_filter is None or all(labels.get(k) == v for k, v in labels_filter.items()):
            return val
    return None


def _gb(bytes_val):
    if bytes_val is None:
        return None
    return round(bytes_val / 1e9, 1)


def _pct(used, total):
    if used and total:
        return round(used / total * 100, 1)
    return None


@tool
def query_qnap_health() -> str:
    """Get QNAP NAS health summary: volumes, CPU, memory, temperatures, fans, disk SMART status, and ZFS filesystem usage.

    Pulls from two exporters:
    - fl-qnap-api-exporter (port 9004): REST API — volumes, RAID status, uptime
    - fl-qnap-snmp-exporter (port 9003): SNMP — CPU, RAM, temperatures, fan RPMs,
      per-ZFS-dataset filesystem usage, network counters

    Returns:
        JSON with system resources, volume usage, fan speeds, filesystem usage, and health indicators.
    """
    # --- Fetch from REST API exporter ---
    try:
        with httpx.Client(timeout=10.0) as client:
            api_resp = client.get("http://fl-qnap-api-exporter:9004/metrics")
            api_resp.raise_for_status()
        m_api = _parse_prometheus(api_resp.text)
    except Exception as e:
        m_api = {}
        api_error = str(e)
    else:
        api_error = None

    # --- Fetch from SNMP exporter ---
    try:
        with httpx.Client(timeout=10.0) as client:
            snmp_resp = client.get("http://fl-qnap-snmp-exporter:9003/metrics")
            snmp_resp.raise_for_status()
        m_snmp = _parse_prometheus(snmp_resp.text)
    except Exception as e:
        m_snmp = {}
        snmp_error = str(e)
    else:
        snmp_error = None

    if not m_api and not m_snmp:
        return json.dumps({"error": f"Both exporters unreachable. API: {api_error}, SNMP: {snmp_error}"})

    # --- CPU / Memory ---
    # SNMP exporter: qnap_cpu_usage_percent, qnap_memory_total_bytes, qnap_memory_used_bytes
    # REST API exporter: same names
    cpu = _first(m_snmp, "qnap_cpu_usage_percent") or _first(m_api, "qnap_cpu_usage_percent")
    mem_used = _first(m_snmp, "qnap_memory_used_bytes") or _first(m_api, "qnap_memory_used_bytes")
    mem_total = _first(m_snmp, "qnap_memory_total_bytes") or _first(m_api, "qnap_memory_total_bytes")
    mem_free = _first(m_snmp, "qnap_memory_free_bytes") or _first(m_api, "qnap_memory_free_bytes")
    mem_pct = _pct(mem_used, mem_total)
    uptime_days = None
    # Both exporters report qnap_uptime_seconds but both are currently unreliable:
    # SNMP returns 0.0 (OID parse bug), API returns exporter process uptime not NAS uptime.
    # Pick the larger value (more likely to be real) and ignore values under 600s (10 min)
    # which are almost certainly exporter restarts, not NAS reboots.
    uptime_snmp = _first(m_snmp, "qnap_uptime_seconds") or 0
    uptime_api = _first(m_api, "qnap_uptime_seconds") or 0
    uptime_s = max(uptime_snmp, uptime_api)
    if uptime_s > 600:
        uptime_days = round(uptime_s / 86400, 1)
    else:
        uptime_days = None  # unreliable — don't report

    # --- Temperatures ---
    # SNMP exporter: qnap_system_temp_celsius, qnap_disk_temp_celsius{disk, model}
    # REST API exporter: qnap_system_temperature_celsius, qnap_disk_temperature_celsius
    temps = {}
    sys_temp = _first(m_snmp, "qnap_system_temp_celsius") or _first(m_api, "qnap_system_temperature_celsius")
    cpu_temp = _first(m_api, "qnap_cpu_temperature_celsius")  # REST API only
    if sys_temp is not None:
        temps["system"] = sys_temp
    if cpu_temp is not None:
        temps["cpu"] = cpu_temp
    # Per-disk temps: SNMP uses qnap_disk_temp_celsius, REST API uses qnap_disk_temperature_celsius
    for labels, val in m_snmp.get("qnap_disk_temp_celsius", []):
        disk = labels.get("disk", "unknown")
        if f"disk_{disk}" not in temps:
            temps[f"disk_{disk}"] = val
    for labels, val in m_api.get("qnap_disk_temperature_celsius", []):
        disk = labels.get("disk", labels.get("slot", "unknown"))
        if f"disk_{disk}" not in temps:
            temps[f"disk_{disk}"] = val

    # --- Fan speeds (SNMP only: qnap_fan_speed_rpm) ---
    fans = {}
    for labels, val in m_snmp.get("qnap_fan_speed_rpm", []):
        fan = labels.get("fan", "unknown")
        fans[fan] = int(val)

    # --- Volumes ---
    # SNMP: qnap_volume_size_bytes, qnap_volume_used_bytes, qnap_volume_free_bytes
    # REST API: qnap_volume_capacity_bytes, qnap_volume_used_bytes, qnap_volume_free_bytes
    # SNMP is preferred source; REST API fills in only when SNMP has no data at all.
    # Do NOT mix per-metric sources — label names differ between exporters (e.g. "Vol1" vs
    # "DataVolume"), which would create phantom duplicate volumes and double-alert.
    volumes = {}
    _snmp_has_volumes = bool(m_snmp.get("qnap_volume_size_bytes"))
    if _snmp_has_volumes:
        for labels, val in m_snmp.get("qnap_volume_size_bytes", []):
            vol = labels.get("volume", "unknown")
            volumes.setdefault(vol, {})["total_gb"] = _gb(val)
        for labels, val in m_snmp.get("qnap_volume_used_bytes", []):
            vol = labels.get("volume", "unknown")
            volumes.setdefault(vol, {})["used_gb"] = _gb(val)
        for labels, val in m_snmp.get("qnap_volume_free_bytes", []):
            vol = labels.get("volume", "unknown")
            volumes.setdefault(vol, {})["free_gb"] = _gb(val)
    else:
        # SNMP exporter down — fall back to REST API entirely
        for labels, val in m_api.get("qnap_volume_capacity_bytes", []):
            vol = labels.get("volume", "unknown")
            volumes.setdefault(vol, {})["total_gb"] = _gb(val)
        for labels, val in m_api.get("qnap_volume_used_bytes", []):
            vol = labels.get("volume", "unknown")
            volumes.setdefault(vol, {})["used_gb"] = _gb(val)
        for labels, val in m_api.get("qnap_volume_free_bytes", []):
            vol = labels.get("volume", "unknown")
            volumes.setdefault(vol, {})["free_gb"] = _gb(val)
    for vol, info in volumes.items():
        info["used_pct"] = _pct(info.get("used_gb"), info.get("total_gb"))

    # --- ZFS/filesystem usage (SNMP hrStorageTable) ---
    # NVR volumes are circular recording — always near 100% by design, never alert on them.
    _NVR_MOUNTS = {"/share/ZFS21_DATA", "/share/ZFS530_DATA"}
    # Friendly names for shares we care about
    _SHARE_NAMES = {
        "/share/ZFS22_DATA": "ssd_share",
        "/share/ZFS19_DATA": "Backups",
        "/share/ZFS20_DATA": "Shared",
        "/share/ZFS3_DATA": "Multimedia",
        "/share/external/DEV3502_1": "external",
    }
    nvr_mounts = _NVR_MOUNTS
    filesystems = {}
    for labels, val in m_snmp.get("qnap_filesystem_used_percent", []):
        mount = labels.get("mount", "unknown")
        filesystems[mount] = {"used_pct": round(val, 1)}
    for labels, val in m_snmp.get("qnap_filesystem_size_bytes", []):
        mount = labels.get("mount", "unknown")
        filesystems.setdefault(mount, {})["total_gb"] = _gb(val)
    for labels, val in m_snmp.get("qnap_filesystem_used_bytes", []):
        mount = labels.get("mount", "unknown")
        filesystems.setdefault(mount, {})["used_gb"] = _gb(val)

    # --- Disks ---
    # SNMP: qnap_disk_status{disk, model} (1=GOOD, 0=FAIL), qnap_disk_temp_celsius{disk, model}
    # REST API: qnap_disk_smart_status{disk/slot}, qnap_disk_temperature_celsius{disk/slot}
    disks = {}
    for labels, val in m_snmp.get("qnap_disk_status", []):
        disk = labels.get("disk", "unknown")
        model = labels.get("model", "")
        disks[disk] = {"smart": "ok" if val == 1 else "warn"}
        if model:
            disks[disk]["model"] = model
    for labels, val in m_api.get("qnap_disk_smart_status", []):
        disk = labels.get("disk", labels.get("slot", "unknown"))
        if disk not in disks:
            disks[disk] = {"smart": "ok" if val == 1 else "warn"}
    for labels, val in m_snmp.get("qnap_disk_temp_celsius", []):
        disk = labels.get("disk", "unknown")
        disks.setdefault(disk, {})["temp_c"] = val
    for labels, val in m_api.get("qnap_disk_temperature_celsius", []):
        disk = labels.get("disk", labels.get("slot", "unknown"))
        if "temp_c" not in disks.setdefault(disk, {}):
            disks[disk]["temp_c"] = val

    # --- Alerts ---
    alerts = []
    if cpu is not None and cpu > 85:
        alerts.append(f"CPU high: {cpu}%")
    if mem_pct is not None and mem_pct > 90:
        alerts.append(f"Memory high: {mem_pct}%")
    for vol, info in volumes.items():
        if info.get("used_pct") and info["used_pct"] > 85:
            alerts.append(f"Volume '{vol}' usage: {info['used_pct']}%")
    for mount, info in filesystems.items():
        if mount in nvr_mounts:
            continue
        friendly = _SHARE_NAMES.get(mount)
        if not friendly:
            continue  # Only report shares we've mapped
        if info.get("used_pct") and info["used_pct"] > 85:
            alerts.append(f"Share '{friendly}' usage: {info['used_pct']}%")
    for temp_name, temp_val in temps.items():
        if temp_val > 65:
            alerts.append(f"High temperature {temp_name}: {temp_val}°C")
    for fan, rpm in fans.items():
        if rpm == 0:
            alerts.append(f"Fan {fan} stopped (0 RPM)")
    for disk, info in disks.items():
        if isinstance(info, dict) and info.get("smart") == "warn":
            alerts.append(f"Disk {disk} SMART warning")

    result: dict = {
        "system": {
            "cpu_pct": cpu,
            "memory_used_gb": _gb(mem_used),
            "memory_total_gb": _gb(mem_total),
            "memory_free_gb": _gb(mem_free),
            "memory_pct": mem_pct,
            "uptime_days": uptime_days,
        },
        "temperatures_c": temps,
        "volumes": volumes,
        "disks": disks,
        "alerts": alerts,
        "healthy": len(alerts) == 0,
    }
    if fans:
        result["fans_rpm"] = fans
    if filesystems:
        # Only include mapped shares with friendly names
        friendly_fs = {}
        for mount, info in filesystems.items():
            if mount in _NVR_MOUNTS:
                continue
            name = _SHARE_NAMES.get(mount)
            if name:
                friendly_fs[name] = info
        if friendly_fs:
            result["filesystems"] = friendly_fs
    if api_error:
        result["api_exporter_error"] = api_error
    if snmp_error:
        result["snmp_exporter_error"] = snmp_error

    return json.dumps(result, indent=2)


def _qnap_get_sid() -> Optional[str]:
    """Authenticate with QNAP and return a session ID, reusing cached token if valid."""
    global _qnap_sid, _qnap_sid_expiry

    with _qnap_sid_lock:
        if _qnap_sid and time.time() < _qnap_sid_expiry:
            return _qnap_sid

        cfg = get_config()
        if not cfg.qnap_api_url or not cfg.qnap_api_user or not cfg.qnap_api_pass:
            return None

        # QNAP authLogin uses MD5-hashed password
        passwd_md5 = hashlib.md5(cfg.qnap_api_pass.encode()).hexdigest()

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(
                    f"{cfg.qnap_api_url.rstrip('/')}/cgi-bin/authLogin.cgi",
                    params={"user": cfg.qnap_api_user, "passwd": passwd_md5},
                )
                resp.raise_for_status()

            root = ET.fromstring(resp.text)
            sid_el = root.find("authSid")
            if sid_el is None or not sid_el.text:
                return None

            _qnap_sid = sid_el.text
            _qnap_sid_expiry = time.time() + 3000  # 50 minutes
            return _qnap_sid

        except Exception:
            return None


@tool
def query_qnap_directory_sizes(
    path: str = "/share/CACHEDEV1_DATA",
    top_n: int = 10,
) -> str:
    """List the largest subdirectories under a given NAS path.

    Uses the QNAP File Station API to fetch folder sizes. Useful for diagnosing
    which directories are consuming space when a volume is filling up.

    Args:
        path: NAS path to analyse (default: primary data volume root).
        top_n: Number of largest subdirectories to return (default 10).

    Returns:
        JSON list of {name, path, size_gb, size_bytes} sorted by size descending,
        or a JSON error object if the API is unavailable.
    """
    cfg = get_config()
    if not cfg.qnap_api_url:
        return json.dumps({"error": "QNAP_API_URL not configured"})

    sid = _qnap_get_sid()
    if not sid:
        return json.dumps({"error": "QNAP authentication failed — check QNAP_API_USER / QNAP_API_PASS"})

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(
                f"{cfg.qnap_api_url.rstrip('/')}/cgi-bin/filemanager/utilRequest.cgi",
                params={
                    "func": "get_tree",
                    "path": path,
                    "tree_type": "folder_size",
                    "sid": sid,
                },
            )
            resp.raise_for_status()

        # Response is JSON: {"data": [{"name": "...", "folder_size": "...", ...}, ...]}
        data = resp.json()
        entries = data.get("data", [])

        results = []
        for entry in entries:
            name = entry.get("name", "")
            size_bytes_raw = entry.get("folder_size") or entry.get("size") or 0
            try:
                size_bytes = int(size_bytes_raw)
            except (TypeError, ValueError):
                size_bytes = 0
            results.append({
                "name": name,
                "path": f"{path.rstrip('/')}/{name}",
                "size_bytes": size_bytes,
                "size_gb": round(size_bytes / 1e9, 2),
            })

        results.sort(key=lambda x: x["size_bytes"], reverse=True)
        return json.dumps(results[:top_n], indent=2)

    except Exception as e:
        # Invalidate cached SID on auth errors so next call re-authenticates
        global _qnap_sid
        _qnap_sid = None
        return json.dumps({"error": f"QNAP directory query failed: {e}"})


def _parse_qulogd_body(body: str) -> dict:
    """Parse a QNAP qulogd syslog message body into structured fields.

    Handles two formats emitted by QNAP:
      Long:  "... qulogd[PID]: event log: Users: X, Source IP: Y, Application: Z, Category: C, Content: MSG"
      Long:  "... qulogd[PID]: conn log: Users: X, Source IP: Y, ..., Action: A"
      Short: "... qulogd:[PID][Application] message"  (duplicate — skipped by caller)
    """
    parsed: dict = {}

    # Extract log type (event/conn/err)
    log_type_m = re.search(r'qulogd\[\d+\]:\s+(event log|conn log|err log):', body)
    if log_type_m:
        parsed["log_type"] = log_type_m.group(1).replace(" log", "")
    else:
        parsed["log_type"] = "event"

    # Key-value pairs in the structured long form
    for field, key in [
        (r'Users:\s*([^,\n]+)', "user"),
        (r'Source IP:\s*([^,\n]+)', "source_ip"),
        (r'Computer name:\s*([^,\n]+)', "computer"),
        (r'Connection type:\s*([^,\n]+)', "connection_type"),
        (r'Accessed resources:\s*([^,\n]+)', "resource"),
        (r'Application:\s*([^,\n]+)', "application"),
        (r'Category:\s*([^,\n]+)', "category"),
        (r'Action:\s*([^,\n]+)', "action"),
        (r'Content:\s*(.+)$', "content"),
    ]:
        m = re.search(field, body)
        if m:
            val = m.group(1).strip()
            if val and val != "---":
                parsed[key] = val

    return parsed


@tool
def query_qnap_events(hours: int = 24) -> str:
    """Get QNAP NAS event log entries: security alerts, login events, warnings, and errors.

    Queries the qulogd syslog stream from the QNAP NAS. Surfaces:
    - Security Center failures (checkup scan errors, policy violations)
    - Login events: SSH/HTTP/SFTP successes and failures
    - Malware Remover scan results
    - Storage & Snapshots warnings
    - Container Station and App Center events
    - Hardware status alerts

    Args:
        hours: Lookback period in hours (default: 24, max: 168)

    Returns:
        JSON with categorised event counts and notable events requiring attention.
    """
    from agent.config import get_config
    hours = min(hours, 168)
    config = get_config()

    # Only query the long-form structured records (avoid duplicate short-form entries)
    query = f"""
    SELECT
        timestamp,
        severity_text,
        body
    FROM signoz_logs.distributed_logs_v2
    WHERE timestamp > toInt64(toUnixTimestamp(now() - INTERVAL {hours} HOUR)) * 1000000000
      AND attributes_string['hostname'] = 'nas'
      AND (body LIKE '%event log:%' OR body LIKE '%conn log:%')
    ORDER BY timestamp DESC
    LIMIT 500
    FORMAT JSONEachRow
    """

    clickhouse_url = f"http://{config.signoz_clickhouse_host}:8123"
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(clickhouse_url, params={
                "user": config.signoz_clickhouse_user,
                "password": config.signoz_clickhouse_password,
                "query": query,
            })
            if resp.status_code != 200:
                return json.dumps({"error": f"ClickHouse HTTP {resp.status_code}: {resp.text[:200]}"})
            rows = [json.loads(line) for line in resp.text.strip().splitlines() if line]
    except Exception as e:
        return json.dumps({"error": str(e)})

    if not rows:
        return json.dumps({"status": "no_events", "message": f"No QNAP events in last {hours}h"})

    # Categorise events
    security_alerts: list = []
    login_failures: list = []
    login_successes: list = []
    warnings: list = []
    info_events: list = []

    # Track counts by application
    app_counts: dict = {}

    for row in rows:
        parsed = _parse_qulogd_body(row.get("body", ""))
        application = parsed.get("application", "Unknown")
        app_counts[application] = app_counts.get(application, 0) + 1

        content = parsed.get("content", parsed.get("action", ""))
        ts_ns = int(row.get("timestamp") or 0)
        ts = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts_ns else ""

        event = {
            "time": ts,
            "application": application,
            "category": parsed.get("category", ""),
            "user": parsed.get("user", ""),
            "source_ip": parsed.get("source_ip", ""),
            "message": content,
        }

        severity = row.get("severity_text", "info")
        action = parsed.get("action", "")

        # Classify
        if parsed.get("log_type") == "conn":
            if "fail" in action.lower():
                login_failures.append(event)
            else:
                login_successes.append(event)
        elif severity in ("warning", "error", "critical") or "<28>" in row.get("body", "") or "<24>" in row.get("body", ""):
            if application == "Security Center":
                security_alerts.append(event)
            else:
                warnings.append(event)
        else:
            info_events.append(event)

    # Build output — only surface what needs attention
    output: dict = {
        "time_range": f"last {hours}h",
        "total_events": len(rows),
        "events_by_application": app_counts,
    }

    if security_alerts:
        output["security_center_alerts"] = security_alerts
    if login_failures:
        output["login_failures"] = login_failures
    # Only include login successes if there were also failures (context) or external IPs
    external_logins = [e for e in login_successes if e.get("source_ip", "").startswith("192.168.") is False and e.get("source_ip")]
    if external_logins:
        output["external_logins"] = external_logins
    if warnings:
        output["warnings"] = warnings[:20]  # cap at 20 to avoid snapshot spam
    if info_events and not (security_alerts or login_failures or warnings):
        output["recent_events"] = info_events[:10]

    # Summarise health
    issues = []
    if security_alerts:
        issues.append(f"{len(security_alerts)} Security Center alert(s)")
    if login_failures:
        issues.append(f"{len(login_failures)} login failure(s)")
    output["issues"] = issues
    output["healthy"] = len(issues) == 0

    return json.dumps(output, indent=2)
