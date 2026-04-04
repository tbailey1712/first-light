"""
Proxmox Backup Server tools — queries PBS for backup job status, last-good
timestamps per VM/CT, and verification task results.

PBS runs at https://192.168.2.8:8007. Auth uses an API token
(root@pam!firstlight) with Audit role on /.

Required ACL: Configuration → Access Control → Permissions → Add
  Path=/  Token=root@pam!firstlight  Role=Audit

.env vars required:
  PBS_HOST              hostname/IP of PBS (default: 192.168.2.8)
  PBS_PORT              API port (default: 8007)
  PBS_TOKEN_ID          e.g. root@pam!firstlight
  PBS_TOKEN_SECRET      UUID token secret
"""

import json
import logging
import ssl
from datetime import datetime, timezone
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)


def _pbs_get(path: str, params: Optional[dict] = None) -> dict | list:
    """Authenticated GET against PBS REST API."""
    cfg = get_config()
    host = getattr(cfg, "pbs_host", None) or "192.168.2.8"
    port = getattr(cfg, "pbs_port", None) or 8007
    token_id = getattr(cfg, "pbs_token_id", None) or "root@pam!firstlight"
    token_secret = getattr(cfg, "pbs_token_secret", None)

    if not token_secret:
        return {"error": "PBS_TOKEN_SECRET not configured in .env"}

    try:
        with httpx.Client(verify=cfg.pbs_verify_ssl, timeout=15.0) as client:
            r = client.get(
                f"https://{host}:{port}/api2/json/{path}",
                headers={"Authorization": f"PBSAPIToken={token_id}:{token_secret}"},
                params=params or {},
            )
        if r.status_code == 200:
            return r.json().get("data", r.json())
        if r.status_code == 403:
            return {"error": "PBS permission denied — add Audit ACL: Path=/ Token=root@pam!firstlight Role=Audit"}
        return {"error": f"HTTP {r.status_code}", "body": r.text[:300]}
    except Exception as e:
        return {"error": str(e)}


def _fmt_ts(ts: Optional[int]) -> Optional[str]:
    """Convert Unix timestamp to ISO string."""
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _age_hours(ts: Optional[int]) -> Optional[float]:
    """Return hours since a Unix timestamp."""
    if not ts:
        return None
    import time
    return round((time.time() - ts) / 3600, 1)


@tool
def query_pbs_backup_status() -> str:
    """Get Proxmox Backup Server status: last successful backup per VM/CT and recent task results.

    For each datastore, returns every backup group (vm, ct, host) with:
    - Last successful snapshot timestamp and age
    - Number of snapshots retained
    - Whether the last backup succeeded or failed

    Also returns recent backup and verify task history (last 48h) to catch
    silent failures — jobs that ran but produced errors.

    Returns:
        JSON with per-datastore backup group status and recent task summary.
    """
    # Get datastores
    datastores = _pbs_get("admin/datastore")
    if isinstance(datastores, dict) and "error" in datastores:
        return json.dumps(datastores)

    if not datastores:
        return json.dumps({
            "error": "No datastores found — check PBS_TOKEN_SECRET in .env and Audit ACL on /",
            "hint": "PBS UI: Configuration → Access Control → Permissions → Add: Path=/ Token=root@pam!firstlight Role=Audit"
        })

    # Get storage usage from the correct endpoint
    usage_list = _pbs_get("status/datastore-usage")
    usage_by_store: dict = {}
    if isinstance(usage_list, list):
        for u in usage_list:
            store = u.get("store")
            if store:
                total = u.get("total", 0)
                avail = u.get("avail", 0)
                used = total - avail if total else 0
                usage_by_store[store] = {
                    "total_gb": round(total / (1024 ** 3), 1),
                    "used_gb": round(used / (1024 ** 3), 1),
                    "avail_gb": round(avail / (1024 ** 3), 1),
                    "used_pct": round(used / total * 100, 1) if total else 0,
                    "estimated_full": _fmt_ts(u.get("estimated-full-date")),
                }

    result = {
        "datastores": [],
        "stale_backups": [],      # Groups with last backup > 26h ago
        "failed_tasks_48h": [],   # Tasks that ended in error
    }

    for ds in datastores:
        store_name = ds.get("store") or ds.get("name")
        if not store_name:
            continue

        sz = usage_by_store.get(store_name, {})
        store_entry = {
            "name": store_name,
            "total_gb": sz.get("total_gb", 0),
            "used_gb": sz.get("used_gb", 0),
            "avail_gb": sz.get("avail_gb", 0),
            "used_pct": sz.get("used_pct", 0),
            "estimated_full": sz.get("estimated_full"),
            "groups": [],
        }

        # List backup groups in this datastore
        groups = _pbs_get(f"admin/datastore/{store_name}/groups")
        if isinstance(groups, dict) and "error" in groups:
            store_entry["error"] = groups["error"]
            result["datastores"].append(store_entry)
            continue

        for group in groups or []:
            backup_type = group.get("backup-type", "")
            backup_id = group.get("backup-id", "")
            last_backup = group.get("last-backup")
            backup_count = group.get("backup-count", 0)

            age = _age_hours(last_backup)
            stale = age is not None and age > 26

            group_entry = {
                "id": f"{backup_type}/{backup_id}",
                "last_backup": _fmt_ts(last_backup),
                "last_backup_age_h": age,
                "snapshot_count": backup_count,
                "stale": stale,
                "owner": group.get("owner"),
            }
            store_entry["groups"].append(group_entry)

            if stale:
                result["stale_backups"].append({
                    "datastore": store_name,
                    "id": f"{backup_type}/{backup_id}",
                    "last_backup_age_h": age,
                    "last_backup": _fmt_ts(last_backup),
                })

        result["datastores"].append(store_entry)

    # Recent tasks (backup + verify) from the last 48h
    import time
    tasks = _pbs_get("nodes/localhost/tasks", {
        "limit": 100,
        "since": int(time.time()) - 172800,  # 48h
    })
    if isinstance(tasks, list):
        task_summary = {"ok": 0, "error": 0, "running": 0, "unknown": 0}
        for task in tasks:
            task_type = task.get("worker_type", "")
            if task_type not in ("backup", "verify", "prune", "garbage_collection"):
                continue
            status = task.get("status", "")
            upid = task.get("upid", "")

            if status == "OK":
                task_summary["ok"] += 1
            elif status and status != "OK" and not status.startswith("running"):
                task_summary["error"] += 1
                result["failed_tasks_48h"].append({
                    "type": task_type,
                    "status": status[:80],
                    "start": _fmt_ts(task.get("starttime")),
                    "end": _fmt_ts(task.get("endtime")),
                    "node": task.get("node"),
                    "upid": upid[:60],
                })
            elif not status:
                task_summary["running"] += 1
            else:
                task_summary["unknown"] += 1

        result["task_summary_48h"] = task_summary
    elif isinstance(tasks, dict) and "error" in tasks:
        result["task_summary_48h"] = {"error": tasks["error"]}

    result["overall_status"] = "critical" if result["failed_tasks_48h"] or result["stale_backups"] else "ok"

    return json.dumps(result, indent=2)


@tool
def query_pbs_prune_policies() -> str:
    """Read Proxmox Backup Server datastore prune and retention policies.

    Returns the prune schedule and keep-* retention settings for each datastore.
    Useful for determining whether a stale backup group is intentionally excluded
    (pruned by policy) vs. a genuine backup failure.

    Returns:
        JSON with per-datastore prune config: schedule, keep_last, keep_hourly,
        keep_daily, keep_weekly, keep_monthly, keep_yearly.
    """
    datastores = _pbs_get("admin/datastore")
    if isinstance(datastores, dict) and "error" in datastores:
        return json.dumps(datastores)

    if not datastores:
        return json.dumps({"error": "No datastores found — check PBS_TOKEN_SECRET and Audit ACL"})

    result = []
    for ds in datastores:
        store_name = ds.get("store") or ds.get("name")
        if not store_name:
            continue

        # Fetch datastore config — contains prune schedule and keep-* settings
        config = _pbs_get(f"admin/datastore/{store_name}/config")
        if isinstance(config, dict) and "error" in config:
            result.append({"datastore": store_name, "error": config["error"]})
            continue

        if not isinstance(config, dict):
            result.append({"datastore": store_name, "error": "Unexpected response format"})
            continue

        result.append({
            "datastore": store_name,
            "prune_schedule": config.get("prune-schedule"),
            "keep_last": config.get("keep-last"),
            "keep_hourly": config.get("keep-hourly"),
            "keep_daily": config.get("keep-daily"),
            "keep_weekly": config.get("keep-weekly"),
            "keep_monthly": config.get("keep-monthly"),
            "keep_yearly": config.get("keep-yearly"),
            "gc_schedule": config.get("gc-schedule"),
            "verify_new": config.get("verify-new"),
        })

    return json.dumps({"datastores": result}, indent=2)
