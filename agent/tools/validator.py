"""
Ethereum Validator health tools — queries Nimbus and Nethermind Prometheus endpoints directly.

Nimbus (consensus):  http://vldtr.mcducklabs.com:8008/metrics
Nethermind (execution): http://vldtr.mcducklabs.com:6060/metrics
"""

import json
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import httpx
from langchain_core.tools import tool

NIMBUS_URL = "http://vldtr.mcducklabs.com:8008/metrics"
NETHERMIND_URL = "http://vldtr.mcducklabs.com:6060/metrics"


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


def _sum_all(metrics, name):
    """Sum all values for a metric across all label sets."""
    return sum(v for _, v in metrics.get(name, [])) or None


@tool
def query_validator_health(hours: int = 24) -> str:
    """Get Ethereum validator health: Nimbus consensus client and Nethermind execution client.

    Queries Prometheus metrics directly from the validator node.
    Returns sync status, peer counts, attestation performance, and balance.

    Args:
        hours: Not used for live metrics, kept for interface consistency.

    Returns:
        JSON with consensus/execution health, attestation effectiveness, alerts.
    """
    alerts = []
    result = {}

    # ── Nimbus (consensus) ──────────────────────────────────────────────────
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(NIMBUS_URL)
            resp.raise_for_status()
        nm = _parse_prometheus(resp.text)

        head_slot = _first(nm, "beacon_head_slot")
        finalized_epoch = _first(nm, "beacon_finalized_epoch")
        peers = _first(nm, "libp2p_peers")
        start_ts = _first(nm, "process_start_time_seconds")

        uptime_hours = None
        if start_ts:
            uptime_hours = round((time.time() - start_ts) / 3600, 1)

        # Balance (in Gwei → ETH)
        balance_gwei = _first(nm, "validator_monitor_balance_gwei", {"validator": "total"})
        eff_balance_gwei = _first(nm, "validator_monitor_effective_balance_gwei", {"validator": "total"})
        balance_eth = round(balance_gwei / 1e9, 6) if balance_gwei else None
        eff_balance_eth = round(eff_balance_gwei / 1e9, 6) if eff_balance_gwei else None

        # Attestation effectiveness (prev epoch)
        att_hits = _first(nm, "validator_monitor_prev_epoch_on_chain_attester_hit_total", {"validator": "total"})
        att_misses = _first(nm, "validator_monitor_prev_epoch_on_chain_attester_miss_total", {"validator": "total"})
        head_hits = _first(nm, "validator_monitor_prev_epoch_on_chain_head_attester_hit_total", {"validator": "total"})
        head_misses = _first(nm, "validator_monitor_prev_epoch_on_chain_head_attester_miss_total", {"validator": "total"})
        target_hits = _first(nm, "validator_monitor_prev_epoch_on_chain_target_attester_hit_total", {"validator": "total"})
        target_misses = _first(nm, "validator_monitor_prev_epoch_on_chain_target_attester_miss_total", {"validator": "total"})

        def _effectiveness(hits, misses):
            if hits is None or misses is None:
                return None
            total = hits + misses
            return round(hits / total * 100, 2) if total > 0 else None

        source_eff = _effectiveness(att_hits, att_misses)
        head_eff = _effectiveness(head_hits, head_misses)
        target_eff = _effectiveness(target_hits, target_misses)

        slashed = _first(nm, "validator_monitor_slashed", {"validator": "total"})
        active = _first(nm, "validator_monitor_active", {"validator": "total"})
        exited = _first(nm, "validator_monitor_exited", {"validator": "total"})

        result["consensus"] = {
            "client": "Nimbus",
            "status": "online",
            "head_slot": int(head_slot) if head_slot else None,
            "finalized_epoch": int(finalized_epoch) if finalized_epoch else None,
            "peers": int(peers) if peers else None,
            "uptime_hours": uptime_hours,
            "balance_eth": balance_eth,
            "effective_balance_eth": eff_balance_eth,
            "validators": {
                "active": int(active) if active else None,
                "exited": int(exited) if exited else None,
                "slashed": int(slashed) if slashed else None,
            },
            "attestation_effectiveness": {
                "source_pct": source_eff,
                "head_pct": head_eff,
                "target_pct": target_eff,
                "prev_epoch_misses": int(att_misses) if att_misses else None,
            },
        }

        # Alerts
        if peers is not None and peers < 10:
            alerts.append(f"CRITICAL: Nimbus peer count low: {int(peers)}")
        if source_eff is not None and source_eff < 95:
            alerts.append(f"WARNING: Source attestation effectiveness {source_eff}% (below 95%)")
        if head_eff is not None and head_eff < 90:
            alerts.append(f"WARNING: Head attestation effectiveness {head_eff}% (below 90%)")
        if slashed and slashed > 0:
            alerts.append(f"CRITICAL: Validator slashed!")
        if exited and exited > 0:
            alerts.append(f"WARNING: {int(exited)} validator(s) exited")

    except Exception as e:
        result["consensus"] = {"client": "Nimbus", "status": "error", "error": str(e)}
        alerts.append(f"CRITICAL: Cannot reach Nimbus metrics endpoint: {e}")

    # ── Nethermind (execution) ──────────────────────────────────────────────
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(NETHERMIND_URL)
            resp.raise_for_status()
        em = _parse_prometheus(resp.text)

        # Total peers across all client types
        total_peers = int(_sum_all(em, "nethermind_sync_peers") or 0)
        blocks = _first(em, "nethermind_blocks")
        transactions = _first(em, "nethermind_transactions")
        reorgs = _first(em, "nethermind_reorganizations")
        mgas_per_sec = _first(em, "nethermind_mgas_per_sec")
        new_payload_ms = _first(em, "nethermind_new_payload_execution_time")

        # Version from any metric label
        version = None
        for _, entries in em.items():
            for labels, _ in entries:
                if "Version" in labels:
                    version = labels["Version"]
                    break
            if version:
                break

        result["execution"] = {
            "client": "Nethermind",
            "version": version,
            "status": "online",
            "peers": total_peers,
            "blocks_processed": int(blocks) if blocks else None,
            "transactions_processed": int(transactions) if transactions else None,
            "reorganizations": int(reorgs) if reorgs else None,
            "mgas_per_sec": round(mgas_per_sec, 1) if mgas_per_sec else None,
            "new_payload_ms": round(new_payload_ms, 1) if new_payload_ms else None,
        }

        if total_peers < 5:
            alerts.append(f"CRITICAL: Nethermind peer count low: {total_peers}")
        if reorgs and reorgs > 5:
            alerts.append(f"WARNING: {int(reorgs)} chain reorganizations detected")

    except Exception as e:
        result["execution"] = {"client": "Nethermind", "status": "error", "error": str(e)}
        alerts.append(f"CRITICAL: Cannot reach Nethermind metrics endpoint: {e}")

    result["alerts"] = alerts
    result["healthy"] = len(alerts) == 0
    result["queried_at"] = datetime.now(timezone.utc).isoformat()

    return json.dumps(result, indent=2)
