"""
Proxmox VE health tools — queries the fl-proxmox-exporter Prometheus endpoint
for node/VM/CT/storage metrics, and the Proxmox REST API directly for VM disk
usage via the QEMU guest agent (get-fsinfo).
"""

import json
import logging
import re
from typing import Dict, List, Optional, Tuple

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)


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


def _gb(bytes_val):
    if bytes_val is None:
        return None
    return round(bytes_val / 1e9, 1)


def _pct(used, total):
    if used and total:
        return round(used / total * 100, 1)
    return None


def _proxmox_api_client() -> Optional[httpx.Client]:
    """Return an httpx client pre-configured with Proxmox API token auth, or None if unconfigured."""
    cfg = get_config()
    if not cfg.proxmox_host or not cfg.proxmox_token_id or not cfg.proxmox_token_secret:
        return None
    return httpx.Client(
        base_url=f"https://{cfg.proxmox_host}:{cfg.proxmox_port}/api2/json",
        headers={"Authorization": f"PVEAPIToken={cfg.proxmox_token_id}={cfg.proxmox_token_secret}"},
        verify=cfg.proxmox_verify_ssl,
        timeout=10.0,
    )


def _get_vm_disk_usage(client: httpx.Client, node: str, vmid: str) -> Optional[dict]:
    """
    Query guest agent get-fsinfo for a running VM.
    Returns {"used_gb": X, "total_gb": Y, "used_pct": Z} or None on failure.
    """
    try:
        resp = client.get(f"/nodes/{node}/qemu/{vmid}/agent/get-fsinfo")
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {}).get("result", [])
        if not isinstance(data, list):
            return None

        # Aggregate across filesystems, dedup by device, skip pseudo-FSes
        SKIP_TYPES = {"tmpfs", "devtmpfs", "overlay", "squashfs"}
        SKIP_MOUNTS = {"/dev", "/proc", "/sys", "/run", "/boot/efi", "/snap"}
        seen_devs: set = set()
        total = used = 0
        for fs in data:
            if fs.get("type") in SKIP_TYPES:
                continue
            mp = fs.get("mountpoint", "")
            if any(mp.startswith(s) for s in SKIP_MOUNTS):
                continue
            # Dedup by block device
            devs = tuple(sorted(d.get("pci-controller-id", "") + d.get("bus-type", "") + str(d.get("dev", ""))
                                for d in (fs.get("disk") or [])))
            if devs and devs in seen_devs:
                continue
            if devs:
                seen_devs.add(devs)
            total += fs.get("total-bytes", 0) or 0
            used += fs.get("used-bytes", 0) or 0

        if total == 0:
            return None
        return {
            "used_gb": _gb(used),
            "total_gb": _gb(total),
            "used_pct": _pct(used, total),
        }
    except Exception as e:
        logger.debug("get-fsinfo failed for vmid %s: %s", vmid, e)
        return None


@tool
def query_proxmox_health() -> str:
    """Get Proxmox VE health summary: node resources, VMs, containers, and storage.

    Returns:
        JSON with node CPU/memory, per-VM/container status, storage usage, and alerts.
    """
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get("http://fl-proxmox-exporter:9002/metrics")
            resp.raise_for_status()
    except Exception as e:
        return json.dumps({"error": f"Could not reach Proxmox exporter: {e}"})

    m = _parse_prometheus(resp.text)

    # --- Node-level metrics ---
    nodes = {}
    for labels, val in m.get("pve_node_cpu_usage_ratio", []):
        node = labels.get("node", "pve")
        nodes.setdefault(node, {})["cpu_pct"] = round(val * 100, 1)
    for labels, val in m.get("pve_node_memory_usage_bytes", []):
        node = labels.get("node", "pve")
        nodes.setdefault(node, {})["mem_used_gb"] = _gb(val)
    for labels, val in m.get("pve_node_memory_total_bytes", []):
        node = labels.get("node", "pve")
        nodes.setdefault(node, {})["mem_total_gb"] = _gb(val)

    for node, info in nodes.items():
        info["mem_pct"] = _pct(
            info.get("mem_used_gb"), info.get("mem_total_gb")
        )

    # --- VMs ---
    vms = {}
    for labels, val in m.get("pve_vm_cpu_usage_ratio", []):
        key = (labels.get("vmid", "?"), labels.get("name", "unknown"))
        vms.setdefault(key, {})["cpu_pct"] = round(val * 100, 1)
    for labels, val in m.get("pve_vm_memory_usage_bytes", []):
        key = (labels.get("vmid", "?"), labels.get("name", "unknown"))
        vms.setdefault(key, {})["mem_used_gb"] = _gb(val)
    for labels, val in m.get("pve_vm_memory_total_bytes", []):
        key = (labels.get("vmid", "?"), labels.get("name", "unknown"))
        vms.setdefault(key, {})["mem_total_gb"] = _gb(val)
    for labels, val in m.get("pve_vm_disk_usage_bytes", []):
        key = (labels.get("vmid", "?"), labels.get("name", "unknown"))
        vms.setdefault(key, {})["disk_used_gb"] = _gb(val)
    for labels, val in m.get("pve_vm_disk_total_bytes", []):
        key = (labels.get("vmid", "?"), labels.get("name", "unknown"))
        vms.setdefault(key, {})["disk_total_gb"] = _gb(val)
    for labels, val in m.get("pve_vm_uptime_seconds", []):
        key = (labels.get("vmid", "?"), labels.get("name", "unknown"))
        vms.setdefault(key, {})["uptime_hours"] = round(val / 3600, 1)
    for labels, val in m.get("pve_vm_status", []):
        key = (labels.get("vmid", "?"), labels.get("name", "unknown"))
        vms.setdefault(key, {})["running"] = val == 1.0
        vms.setdefault(key, {})["status"] = labels.get("status", "unknown")

    # Fetch real VM disk usage via guest agent (requires Proxmox API token + qemu-guest-agent)
    cfg = get_config()
    pve_node = cfg.proxmox_node or "pve"
    pve_client = _proxmox_api_client()

    vm_list = []
    for (vmid, name), info in vms.items():
        info["vmid"] = vmid
        info["name"] = name
        info["mem_pct"] = _pct(info.get("mem_used_gb"), info.get("mem_total_gb"))

        # Try guest agent disk stats for running VMs
        disk_info = None
        if pve_client and info.get("running"):
            disk_info = _get_vm_disk_usage(pve_client, pve_node, vmid)

        if disk_info:
            info["disk_used_gb"] = disk_info["used_gb"]
            info["disk_total_gb"] = disk_info["total_gb"]
            info["disk_pct"] = disk_info["used_pct"]
            info["disk_source"] = "guest_agent"
        else:
            # Proxmox API returns write counters (not actual usage) for VMs without agent
            info["disk_pct"] = None
            info["disk_source"] = "unavailable"

        vm_list.append(info)
    vm_list.sort(key=lambda x: x.get("vmid", ""))

    if pve_client:
        pve_client.close()

    # --- Containers ---
    cts = {}
    for labels, val in m.get("pve_ct_cpu_usage_ratio", []):
        key = (labels.get("ctid", "?"), labels.get("name", "unknown"))
        cts.setdefault(key, {})["cpu_pct"] = round(val * 100, 1)
    for labels, val in m.get("pve_ct_memory_usage_bytes", []):
        key = (labels.get("ctid", "?"), labels.get("name", "unknown"))
        cts.setdefault(key, {})["mem_used_gb"] = _gb(val)
    for labels, val in m.get("pve_ct_memory_total_bytes", []):
        key = (labels.get("ctid", "?"), labels.get("name", "unknown"))
        cts.setdefault(key, {})["mem_total_gb"] = _gb(val)
    for labels, val in m.get("pve_ct_disk_usage_bytes", []):
        key = (labels.get("ctid", "?"), labels.get("name", "unknown"))
        cts.setdefault(key, {})["disk_used_gb"] = _gb(val)
    for labels, val in m.get("pve_ct_disk_total_bytes", []):
        key = (labels.get("ctid", "?"), labels.get("name", "unknown"))
        cts.setdefault(key, {})["disk_total_gb"] = _gb(val)
    for labels, val in m.get("pve_ct_uptime_seconds", []):
        key = (labels.get("ctid", "?"), labels.get("name", "unknown"))
        cts.setdefault(key, {})["uptime_hours"] = round(val / 3600, 1)
    for labels, val in m.get("pve_ct_status", []):
        key = (labels.get("ctid", "?"), labels.get("name", "unknown"))
        cts.setdefault(key, {})["running"] = val == 1.0
        cts.setdefault(key, {})["status"] = labels.get("status", "unknown")

    ct_list = []
    for (ctid, name), info in cts.items():
        info["ctid"] = ctid
        info["name"] = name
        info["disk_pct"] = _pct(info.get("disk_used_gb"), info.get("disk_total_gb"))
        info["mem_pct"] = _pct(info.get("mem_used_gb"), info.get("mem_total_gb"))
        ct_list.append(info)
    ct_list.sort(key=lambda x: x.get("ctid", ""))

    # --- Storage ---
    storage = {}
    for labels, val in m.get("pve_storage_usage_bytes", []):
        key = labels.get("storage", "unknown")
        storage.setdefault(key, {})["used_gb"] = _gb(val)
    for labels, val in m.get("pve_storage_total_bytes", []):
        key = labels.get("storage", "unknown")
        storage.setdefault(key, {})["total_gb"] = _gb(val)
    for key, info in storage.items():
        info["used_pct"] = _pct(info.get("used_gb"), info.get("total_gb"))

    # --- Alerts ---
    alerts = []
    for node, info in nodes.items():
        if info.get("cpu_pct", 0) > 85:
            alerts.append(f"Node {node} CPU high: {info['cpu_pct']}%")
        if info.get("mem_pct", 0) > 90:
            alerts.append(f"Node {node} memory high: {info['mem_pct']}%")

    # Stopped VMs are reported in the vm_list data but NOT raised as alerts —
    # the agent cannot distinguish intentionally-stopped from unexpectedly-stopped.

    for v in vm_list:
        if v.get("disk_pct") and v["disk_pct"] > 80:
            alerts.append(f"VM {v['name']} disk usage: {v['disk_pct']}% (guest agent)")

    for s, info in storage.items():
        if info.get("used_pct", 0) and info["used_pct"] > 85:
            alerts.append(f"Storage {s} usage: {info['used_pct']}%")

    return json.dumps({
        "nodes": nodes,
        "vms": vm_list,
        "containers": ct_list,
        "storage": storage,
        "alerts": alerts,
        "healthy": len(alerts) == 0,
    }, indent=2)


@tool
def query_proxmox_vm_configs() -> str:
    """Read VM and container configuration from Proxmox API.

    Returns per-VM/CT configuration: CPU cores, RAM allocation, disk sizes,
    boot order, agent status, and backup schedule (via Proxmox backup job configs).

    Useful for: verifying vm/115 backup schedule, confirming which VMs exist,
    checking HA VM disk allocation, identifying VMs without backup jobs.

    Returns:
        JSON with vms and containers lists (config details) plus backup_jobs list.
    """
    cfg = get_config()
    client = _proxmox_api_client()
    if client is None:
        return json.dumps({
            "error": "Proxmox API not configured — set PROXMOX_HOST, PROXMOX_TOKEN_ID, PROXMOX_TOKEN_SECRET"
        })

    node = cfg.proxmox_node or "pve"

    try:
        vms = []
        cts = []

        # --- VMs ---
        resp = client.get(f"/nodes/{node}/qemu")
        if resp.status_code == 200:
            for vm in resp.json().get("data", []):
                vmid = vm.get("vmid")
                # Fetch full config for this VM
                cfg_resp = client.get(f"/nodes/{node}/qemu/{vmid}/config")
                if cfg_resp.status_code != 200:
                    vms.append({"vmid": vmid, "name": vm.get("name"), "error": f"HTTP {cfg_resp.status_code}"})
                    continue
                c = cfg_resp.json().get("data", {})

                # Parse disk sizes
                disks = {}
                for key, val in c.items():
                    if key.startswith(("scsi", "virtio", "ide", "sata")) and isinstance(val, str) and "size=" in val:
                        # e.g. "local-lvm:vm-100-disk-0,size=32G"
                        size_part = next((p for p in val.split(",") if p.startswith("size=")), "")
                        disks[key] = size_part.replace("size=", "") if size_part else val.split(",")[0]

                vms.append({
                    "vmid": vmid,
                    "name": vm.get("name"),
                    "status": vm.get("status"),
                    "cores": c.get("cores", c.get("sockets", 1)),
                    "memory_mb": c.get("memory"),
                    "agent_enabled": bool(c.get("agent", "").startswith("enabled=1") if isinstance(c.get("agent"), str) else c.get("agent")),
                    "disks": disks,
                    "tags": c.get("tags", ""),
                    "onboot": c.get("onboot", 0),
                })

        # --- Containers ---
        resp = client.get(f"/nodes/{node}/lxc")
        if resp.status_code == 200:
            for ct in resp.json().get("data", []):
                ctid = ct.get("vmid")
                cfg_resp = client.get(f"/nodes/{node}/lxc/{ctid}/config")
                if cfg_resp.status_code != 200:
                    cts.append({"ctid": ctid, "name": ct.get("name"), "error": f"HTTP {cfg_resp.status_code}"})
                    continue
                c = cfg_resp.json().get("data", {})

                # Parse rootfs and mount points
                disks = {}
                for key in ("rootfs",) + tuple(f"mp{i}" for i in range(10)):
                    val = c.get(key)
                    if val and isinstance(val, str):
                        size_part = next((p for p in val.split(",") if p.startswith("size=")), "")
                        disks[key] = size_part.replace("size=", "") if size_part else val.split(",")[0]

                cts.append({
                    "ctid": ctid,
                    "name": ct.get("name"),
                    "status": ct.get("status"),
                    "cores": c.get("cores"),
                    "memory_mb": c.get("memory"),
                    "swap_mb": c.get("swap"),
                    "disks": disks,
                    "onboot": c.get("onboot", 0),
                })

        # --- Backup jobs ---
        backup_jobs = []
        resp = client.get("/cluster/backup")
        if resp.status_code == 200:
            for job in resp.json().get("data", []):
                backup_jobs.append({
                    "id": job.get("id"),
                    "enabled": bool(job.get("enabled", 1)),
                    "schedule": job.get("schedule"),
                    "storage": job.get("storage"),
                    "vmids": job.get("vmid", "all"),
                    "mode": job.get("mode", "snapshot"),
                    "comment": job.get("comment", ""),
                })

        client.close()
        return json.dumps({
            "node": node,
            "vms": sorted(vms, key=lambda x: x.get("vmid", 0)),
            "containers": sorted(cts, key=lambda x: x.get("ctid", 0)),
            "backup_jobs": backup_jobs,
        }, indent=2)

    except Exception as e:
        if not client.is_closed:
            client.close()
        return json.dumps({"error": str(e)})
