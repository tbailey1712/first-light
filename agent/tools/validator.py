"""
Ethereum Validator health tools — queries Nimbus and Nethermind Prometheus endpoints directly.

Nimbus (consensus):  http://vldtr.mcducklabs.com:8008/metrics
Nethermind (execution): http://vldtr.mcducklabs.com:6060/metrics
"""

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from langchain_core.tools import tool
from langfuse import observe

from agent.config import get_config

_REDIS_BALANCE_KEY = "fl:validator:balance_eth"
_REDIS_TTL = 60 * 60 * 50  # 50 hours — survives up to two daily runs


def _redis_get(key: str) -> Optional[str]:
    try:
        import redis as _redis
        r = _redis.from_url(get_config().redis_url, decode_responses=True)
        return r.get(key)
    except Exception:
        return None


def _redis_set(key: str, value: str, ttl: int = _REDIS_TTL) -> None:
    try:
        import redis as _redis
        r = _redis.from_url(get_config().redis_url, decode_responses=True)
        r.setex(key, ttl, value)
    except Exception:
        pass


def _nimbus_url() -> str:
    cfg = get_config()
    host = cfg.validator_host or "vldtr.mcducklabs.com"
    return f"http://{host}:{cfg.consensus_metrics_port}/metrics"


def _nethermind_url() -> str:
    cfg = get_config()
    host = cfg.validator_host or "vldtr.mcducklabs.com"
    return f"http://{host}:{cfg.execution_metrics_port}/metrics"


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


@observe(as_type="span", name="validator.fetch_nimbus")
def _fetch_nimbus_metrics() -> Optional[Dict]:
    """Fetch and parse Nimbus consensus client Prometheus metrics."""
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(_nimbus_url())
        resp.raise_for_status()
    return _parse_prometheus(resp.text)


@observe(as_type="span", name="validator.fetch_nethermind")
def _fetch_nethermind_metrics() -> Optional[Dict]:
    """Fetch and parse Nethermind execution client Prometheus metrics."""
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(_nethermind_url())
        resp.raise_for_status()
    return _parse_prometheus(resp.text)


@tool
@observe(as_type="span", name="validator.query_health")
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
        nm = _fetch_nimbus_metrics()

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

        # Attestation inclusion distance (DATA-3) — lower is better; 1 = ideal
        min_inclusion_distance = _first(
            nm,
            "validator_monitor_prev_epoch_attestation_block_min_inclusion_distance",
            {"validator": "total"},
        )
        block_inclusions = _first(
            nm,
            "validator_monitor_prev_epoch_attestation_block_inclusions",
            {"validator": "total"},
        )
        min_att_delay_s = _first(
            nm,
            "validator_monitor_prev_epoch_attestations_min_delay_seconds",
            {"validator": "total"},
        )

        # Block proposals: hit count (times our block was included after an epoch)
        block_hit = _first(nm, "validator_monitor_block_hit", {"validator": "total"})
        beacon_block_count = _first(nm, "validator_monitor_beacon_block", {"validator": "total"})

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

        # DATA-2: Balance delta vs previous run
        balance_delta_eth = None
        balance_trend = "unknown"
        if balance_eth is not None:
            prev_raw = _redis_get(_REDIS_BALANCE_KEY)
            if prev_raw is not None:
                try:
                    prev_balance = float(prev_raw)
                    balance_delta_eth = round(balance_eth - prev_balance, 6)
                    if balance_delta_eth > 0:
                        balance_trend = "increasing"
                    elif balance_delta_eth < -0.001:
                        balance_trend = "decreasing"
                    else:
                        balance_trend = "stable"
                except (ValueError, TypeError):
                    pass
            _redis_set(_REDIS_BALANCE_KEY, str(balance_eth))

        result["consensus"] = {
            "client": "Nimbus",
            "status": "online",
            "head_slot": int(head_slot) if head_slot else None,
            "finalized_epoch": int(finalized_epoch) if finalized_epoch else None,
            "peers": int(peers) if peers else None,
            "uptime_hours": uptime_hours,
            "balance_eth": balance_eth,
            "effective_balance_eth": eff_balance_eth,
            "balance_delta_eth": balance_delta_eth,
            "balance_trend": balance_trend,
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
                "min_inclusion_distance": int(min_inclusion_distance) if min_inclusion_distance is not None else None,
                "block_inclusions": int(block_inclusions) if block_inclusions is not None else None,
                "min_attestation_delay_s": round(min_att_delay_s, 3) if min_att_delay_s is not None else None,
            },
            "block_proposals": {
                "blocks_seen": int(beacon_block_count) if beacon_block_count is not None else None,
                "blocks_included": int(block_hit) if block_hit is not None else None,
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
        if balance_delta_eth is not None and balance_delta_eth < -0.01:
            alerts.append(f"WARNING: Balance decreased by {abs(balance_delta_eth):.6f} ETH since last check")
        if min_inclusion_distance is not None and min_inclusion_distance > 3:
            alerts.append(f"WARNING: Attestation min inclusion distance {int(min_inclusion_distance)} slots (ideal: 1)")

    except Exception as e:
        result["consensus"] = {"client": "Nimbus", "status": "error", "error": str(e)}
        alerts.append(f"CRITICAL: Cannot reach Nimbus metrics endpoint: {e}")

    # ── Nethermind (execution) ──────────────────────────────────────────────
    try:
        em = _fetch_nethermind_metrics()

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
