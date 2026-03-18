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
        # metric_name{label="v",...} value [timestamp]
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
    """Get first matching metric value."""
    for labels, val in metrics.get(name, []):
        if labels_filter is None or all(labels.get(k) == v for k, v in labels_filter.items()):
            return val
    return None


def _gb(bytes_val):
    if bytes_val is None:
        return None
    return round(bytes_val / 1e9, 1)


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
    cpu = _first(m, "qnap_system_cpu_usage_percent")
    mem_used = _first(m, "qnap_system_memory_used_bytes")
    mem_total = _first(m, "qnap_system_memory_total_bytes")
    mem_pct = round(mem_used / mem_total * 100, 1) if mem_used and mem_total else None

    # --- Temperatures ---
    temps = {}
    for labels, val in m.get("qnap_temperature_celsius", []):
        comp = labels.get("component", labels.get("sensor", "unknown"))
        temps[comp] = val

    # --- Volumes ---
    volumes = {}
    for labels, val in m.get("qnap_volume_size_total_bytes", []):
        vol = labels.get("volume", labels.get("name", "unknown"))
        volumes.setdefault(vol, {})["total_gb"] = _gb(val)
    for labels, val in m.get("qnap_volume_size_used_bytes", []):
        vol = labels.get("volume", labels.get("name", "unknown"))
        volumes.setdefault(vol, {})["used_gb"] = _gb(val)
    for labels, val in m.get("qnap_volume_status", []):
        vol = labels.get("volume", labels.get("name", "unknown"))
        volumes.setdefault(vol, {})["status"] = "ready" if val == 1 else "degraded"

    for vol, info in volumes.items():
        if info.get("total_gb") and info.get("used_gb"):
            info["used_pct"] = round(info["used_gb"] / info["total_gb"] * 100, 1)

    # --- Disks ---
    disks = {}
    for labels, val in m.get("qnap_disk_smart_status", []):
        disk = labels.get("disk", labels.get("slot", "unknown"))
        disks[disk] = "ok" if val == 1 else "warn"
    for labels, val in m.get("qnap_disk_temperature_celsius", []):
        disk = labels.get("disk", labels.get("slot", "unknown"))
        disks.setdefault(disk, {})
        if isinstance(disks[disk], str):
            disks[disk] = {"smart": disks[disk], "temp_c": val}

    # --- Alerts ---
    alerts = []
    if cpu and cpu > 85:
        alerts.append(f"CPU high: {cpu}%")
    if mem_pct and mem_pct > 90:
        alerts.append(f"Memory high: {mem_pct}%")
    for vol, info in volumes.items():
        if info.get("used_pct", 0) > 85:
            alerts.append(f"Volume {vol} disk usage: {info['used_pct']}%")
        if info.get("status") == "degraded":
            alerts.append(f"Volume {vol} is DEGRADED")
    for temp_name, temp_val in temps.items():
        if temp_val > 65:
            alerts.append(f"High temperature {temp_name}: {temp_val}°C")

    return json.dumps({
        "system": {
            "cpu_pct": cpu,
            "memory_used_gb": _gb(mem_used),
            "memory_total_gb": _gb(mem_total),
            "memory_pct": mem_pct,
        },
        "temperatures_c": temps,
        "volumes": volumes,
        "disks": disks,
        "alerts": alerts,
        "healthy": len(alerts) == 0,
    }, indent=2)
