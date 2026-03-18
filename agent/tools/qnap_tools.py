"""
QNAP NAS health tools — queries the fl-qnap-api-exporter Prometheus endpoint.
"""

import json
import re
from typing import Dict, List, Tuple

import httpx
from langchain_core.tools import tool


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
    """Get QNAP NAS health summary: volumes, CPU, memory, temperatures, disk SMART status.

    Returns:
        JSON with system resources, volume usage, and health indicators.
    """
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get("http://fl-qnap-api-exporter:9004/metrics")
            resp.raise_for_status()
    except Exception as e:
        return json.dumps({"error": f"Could not reach QNAP exporter: {e}"})

    m = _parse_prometheus(resp.text)

    # --- CPU / Memory ---
    cpu = _first(m, "qnap_cpu_usage_percent")
    mem_used = _first(m, "qnap_memory_used_bytes")
    mem_total = _first(m, "qnap_memory_total_bytes")
    mem_free = _first(m, "qnap_memory_free_bytes")
    mem_pct = _pct(mem_used, mem_total)
    uptime_days = None
    uptime_s = _first(m, "qnap_uptime_seconds")
    if uptime_s:
        uptime_days = round(uptime_s / 86400, 1)

    # --- Temperatures ---
    temps = {}
    cpu_temp = _first(m, "qnap_cpu_temperature_celsius")
    sys_temp = _first(m, "qnap_system_temperature_celsius")
    if cpu_temp is not None:
        temps["cpu"] = cpu_temp
    if sys_temp is not None:
        temps["system"] = sys_temp
    # Per-disk temps
    for labels, val in m.get("qnap_disk_temperature_celsius", []):
        disk = labels.get("disk", labels.get("slot", "unknown"))
        temps[f"disk_{disk}"] = val

    # --- Volumes ---
    volumes = {}
    for labels, val in m.get("qnap_volume_capacity_bytes", []):
        vol = labels.get("volume", "unknown")
        pool = labels.get("pool", "")
        key = f"{vol} ({pool})" if pool and pool != "unknown" else vol
        volumes.setdefault(key, {})["total_gb"] = _gb(val)
    for labels, val in m.get("qnap_volume_used_bytes", []):
        vol = labels.get("volume", "unknown")
        pool = labels.get("pool", "")
        key = f"{vol} ({pool})" if pool and pool != "unknown" else vol
        volumes.setdefault(key, {})["used_gb"] = _gb(val)
    for labels, val in m.get("qnap_volume_free_bytes", []):
        vol = labels.get("volume", "unknown")
        pool = labels.get("pool", "")
        key = f"{vol} ({pool})" if pool and pool != "unknown" else vol
        volumes.setdefault(key, {})["free_gb"] = _gb(val)

    for vol, info in volumes.items():
        info["used_pct"] = _pct(info.get("used_gb"), info.get("total_gb"))

    # --- Disks ---
    disks = {}
    for labels, val in m.get("qnap_disk_smart_status", []):
        disk = labels.get("disk", labels.get("slot", "unknown"))
        disks[disk] = {"smart": "ok" if val == 1 else "warn"}
    for labels, val in m.get("qnap_disk_temperature_celsius", []):
        disk = labels.get("disk", labels.get("slot", "unknown"))
        disks.setdefault(disk, {})["temp_c"] = val

    # --- Alerts ---
    alerts = []
    if cpu is not None and cpu > 85:
        alerts.append(f"CPU high: {cpu}%")
    if mem_pct is not None and mem_pct > 90:
        alerts.append(f"Memory high: {mem_pct}%")
    for vol, info in volumes.items():
        if info.get("used_pct") and info["used_pct"] > 85:
            alerts.append(f"Volume '{vol}' usage: {info['used_pct']}%")
    for temp_name, temp_val in temps.items():
        if temp_val > 65:
            alerts.append(f"High temperature {temp_name}: {temp_val}°C")
    for disk, info in disks.items():
        if isinstance(info, dict) and info.get("smart") == "warn":
            alerts.append(f"Disk {disk} SMART warning")

    return json.dumps({
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
    }, indent=2)
