"""
Proxmox VE health tools — queries the Proxmox REST API for node/VM/CT/storage
metrics, and the QEMU guest agent (get-fsinfo) for real VM disk usage.
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

    Queries the Proxmox REST API directly for live node, VM, container, and
    storage status.

    Returns:
        JSON with node CPU/memory, per-VM/container status, storage usage, and alerts.
    """
    cfg = get_config()
    client = _proxmox_api_client()
    if client is None:
        return json.dumps({
            "error": "Proxmox API not configured — set PROXMOX_HOST, PROXMOX_TOKEN_ID, PROXMOX_TOKEN_SECRET"
        })

    node = cfg.proxmox_node or "pve"

    try:
        # --- Node-level metrics ---
        nodes = {}
        resp = client.get(f"/nodes/{node}/status")
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            cpu_val = d.get("cpu")
            mem_info = d.get("memory", {})
            nodes[node] = {
                "cpu_pct": round(cpu_val * 100, 1) if cpu_val is not None else None,
                "mem_used_gb": _gb(mem_info.get("used")),
                "mem_total_gb": _gb(mem_info.get("total")),
                "uptime_hours": round(d.get("uptime", 0) / 3600, 1),
            }
            nodes[node]["mem_pct"] = _pct(mem_info.get("used"), mem_info.get("total"))

        # --- VMs ---
        vm_list = []
        resp = client.get(f"/nodes/{node}/qemu")
        if resp.status_code == 200:
            for vm in resp.json().get("data", []):
                vmid = str(vm.get("vmid", "?"))
                running = vm.get("status") == "running"
                info = {
                    "vmid": vmid,
                    "name": vm.get("name", "unknown"),
                    "status": vm.get("status", "unknown"),
                    "running": running,
                    "cpu_pct": round(vm.get("cpu", 0) * 100, 1) if running else 0,
                    "mem_used_gb": _gb(vm.get("mem")),
                    "mem_total_gb": _gb(vm.get("maxmem")),
                    "uptime_hours": round(vm.get("uptime", 0) / 3600, 1),
                }
                info["mem_pct"] = _pct(vm.get("mem"), vm.get("maxmem"))

                # Try guest agent for real disk usage on running VMs
                disk_info = None
                if running:
                    disk_info = _get_vm_disk_usage(client, node, vmid)

                if disk_info:
                    info["disk_used_gb"] = disk_info["used_gb"]
                    info["disk_total_gb"] = disk_info["total_gb"]
                    info["disk_pct"] = disk_info["used_pct"]
                    info["disk_source"] = "guest_agent"
                else:
                    info["disk_pct"] = None
                    info["disk_source"] = "unavailable"

                vm_list.append(info)
        vm_list.sort(key=lambda x: x.get("vmid", ""))

        # --- Containers ---
        ct_list = []
        resp = client.get(f"/nodes/{node}/lxc")
        if resp.status_code == 200:
            for ct in resp.json().get("data", []):
                ctid = str(ct.get("vmid", "?"))
                running = ct.get("status") == "running"
                info = {
                    "ctid": ctid,
                    "name": ct.get("name", "unknown"),
                    "status": ct.get("status", "unknown"),
                    "running": running,
                    "cpu_pct": round(ct.get("cpu", 0) * 100, 1) if running else 0,
                    "mem_used_gb": _gb(ct.get("mem")),
                    "mem_total_gb": _gb(ct.get("maxmem")),
                    "disk_used_gb": _gb(ct.get("disk")),
                    "disk_total_gb": _gb(ct.get("maxdisk")),
                    "uptime_hours": round(ct.get("uptime", 0) / 3600, 1),
                }
                info["mem_pct"] = _pct(ct.get("mem"), ct.get("maxmem"))
                info["disk_pct"] = _pct(ct.get("disk"), ct.get("maxdisk"))
                ct_list.append(info)
        ct_list.sort(key=lambda x: x.get("ctid", ""))

        # --- Storage ---
        storage = {}
        resp = client.get(f"/nodes/{node}/storage", params={"content": "images,rootdir,backup"})
        if resp.status_code == 200:
            for s in resp.json().get("data", []):
                name = s.get("storage", "unknown")
                if not s.get("active"):
                    continue
                storage[name] = {
                    "used_gb": _gb(s.get("used")),
                    "total_gb": _gb(s.get("total")),
                    "used_pct": _pct(s.get("used"), s.get("total")),
                }

        client.close()

        # --- Alerts ---
        alerts = []
        for n, info in nodes.items():
            if (info.get("cpu_pct") or 0) > 85:
                alerts.append(f"Node {n} CPU high: {info['cpu_pct']}%")
            if (info.get("mem_pct") or 0) > 90:
                alerts.append(f"Node {n} memory high: {info['mem_pct']}%")

        for v in vm_list:
            if v.get("disk_pct") and v["disk_pct"] > 80:
                alerts.append(f"VM {v['name']} disk usage: {v['disk_pct']}% (guest agent)")

        for s, info in storage.items():
            if (info.get("used_pct") or 0) > 85:
                alerts.append(f"Storage {s} usage: {info['used_pct']}%")

        return json.dumps({
            "nodes": nodes,
            "vms": vm_list,
            "containers": ct_list,
            "storage": storage,
            "alerts": alerts,
            "healthy": len(alerts) == 0,
        }, indent=2)

    except Exception as e:
        if not client.is_closed:
            client.close()
        return json.dumps({"error": str(e)})


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


@tool
def query_proxmox_trends(timeframe: str = "day") -> str:
    """Get historical CPU and memory trend data for the Proxmox node and all VMs/containers.

    Reads PVE RRD (round-robin database) data — the same data source used by the
    Proxmox web UI graphs. Useful for identifying sustained high resource usage,
    spotting workload spikes, and understanding whether current metrics are anomalous.

    Args:
        timeframe: One of "hour" (~1min resolution), "day" (~30min resolution),
                   "week" (~3.5hr resolution), "month" (~12hr resolution).
                   Default: "day".

    Returns:
        JSON with peak and average CPU/memory for the node and each VM/CT over
        the requested period, plus a list of any resources that exceeded 80% average.
    """
    cfg = get_config()
    client = _proxmox_api_client()
    if client is None:
        return json.dumps({
            "error": "Proxmox API not configured — set PROXMOX_HOST, PROXMOX_TOKEN_ID, PROXMOX_TOKEN_SECRET"
        })

    valid_timeframes = {"hour", "day", "week", "month"}
    if timeframe not in valid_timeframes:
        timeframe = "day"

    node = cfg.proxmox_node or "pve"

    def _summarise_rrd(data: list, name: str, id_key: str, id_val) -> dict:
        """Compute peak/avg CPU and memory from an RRD data list."""
        cpu_vals = [p["cpu"] for p in data if p.get("cpu") is not None]
        mem_vals = [p["mem"] for p in data if p.get("mem") is not None]
        maxmem_vals = [p["maxmem"] for p in data if p.get("maxmem") is not None]

        mem_pct_vals = []
        for p in data:
            if p.get("mem") and p.get("maxmem") and p["maxmem"] > 0:
                mem_pct_vals.append(p["mem"] / p["maxmem"] * 100)

        result: dict = {id_key: id_val, "name": name}

        if cpu_vals:
            result["cpu_avg_pct"] = round(sum(cpu_vals) / len(cpu_vals) * 100, 1)
            result["cpu_peak_pct"] = round(max(cpu_vals) * 100, 1)
        if mem_pct_vals:
            result["mem_avg_pct"] = round(sum(mem_pct_vals) / len(mem_pct_vals), 1)
            result["mem_peak_pct"] = round(max(mem_pct_vals), 1)
        if mem_vals and maxmem_vals:
            result["mem_total_gb"] = _gb(maxmem_vals[-1])

        return result

    try:
        results = {}

        # --- Node trend ---
        resp = client.get(f"/nodes/{node}/rrddata", params={"timeframe": timeframe, "cf": "AVERAGE"})
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            results["node"] = _summarise_rrd(data, node, "node", node)

        # --- VMs ---
        vm_trends = []
        resp = client.get(f"/nodes/{node}/qemu")
        if resp.status_code == 200:
            for vm in resp.json().get("data", []):
                vmid = vm.get("vmid")
                name = vm.get("name", str(vmid))
                rrd_resp = client.get(
                    f"/nodes/{node}/qemu/{vmid}/rrddata",
                    params={"timeframe": timeframe, "cf": "AVERAGE"},
                )
                if rrd_resp.status_code == 200:
                    vm_trends.append(_summarise_rrd(rrd_resp.json().get("data", []), name, "vmid", vmid))
        results["vms"] = sorted(vm_trends, key=lambda x: str(x.get("vmid", "")))

        # --- Containers ---
        ct_trends = []
        resp = client.get(f"/nodes/{node}/lxc")
        if resp.status_code == 200:
            for ct in resp.json().get("data", []):
                ctid = ct.get("vmid")
                name = ct.get("name", str(ctid))
                rrd_resp = client.get(
                    f"/nodes/{node}/lxc/{ctid}/rrddata",
                    params={"timeframe": timeframe, "cf": "AVERAGE"},
                )
                if rrd_resp.status_code == 200:
                    ct_trends.append(_summarise_rrd(rrd_resp.json().get("data", []), name, "ctid", ctid))
        results["containers"] = sorted(ct_trends, key=lambda x: str(x.get("ctid", "")))

        # --- Attention list: anything averaging >80% CPU or memory ---
        attention = []
        for item in [results.get("node")] + results["vms"] + results["containers"]:
            if not item:
                continue
            name = item.get("name", "?")
            if item.get("cpu_avg_pct", 0) > 80:
                attention.append(f"{name}: avg CPU {item['cpu_avg_pct']}% over {timeframe}")
            if item.get("mem_avg_pct", 0) > 80:
                attention.append(f"{name}: avg memory {item['mem_avg_pct']}% over {timeframe}")
        results["attention"] = attention
        results["timeframe"] = timeframe

        client.close()
        return json.dumps(results, indent=2)

    except Exception as e:
        if not client.is_closed:
            client.close()
        return json.dumps({"error": str(e)})
