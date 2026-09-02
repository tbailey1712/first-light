"""
Episodic memory for cross-run pattern detection in daily reports.

Uses LangGraph's PostgresStore to persist facts across daily report runs:
- Repeat offender IPs (external IPs flagged in multiple consecutive reports)
- Domain severity trends (escalating or sustained warning/critical states)
- Finding count trends (rising critical/warning counts per domain)

All data is extracted deterministically from DomainResult — no extra LLM calls.
"""

import ipaddress
import logging
from datetime import date
from typing import Any

from langgraph.store.base import BaseStore

logger = logging.getLogger(__name__)

_MAX_HISTORY = 7

_NS_IPS = ("episodic", "ips")
_NS_SEVERITY = ("episodic", "severity")
_NS_FINDINGS = ("episodic", "findings")


# --- Connection pool ---------------------------------------------------------
#
# Neon is serverless: its proxy closes connections that have been idle for a
# few minutes, server-side. The daily report opens the PostgresStore at graph
# start and does not touch it again until synthesis ~8-10 minutes later, by
# which point the pooled connection is dead. The pool handed it out anyway, so
# every read failed with "consuming input failed: SSL connection has been closed
# unexpectedly" while the write at the end of the run (on a fresh connection)
# succeeded. Net effect: episodic memory was write-only, and no run ever logged
# "Episodic memory context injected".
#
# TCP keepalives do not help — the close is a deliberate server-side action, not
# a dropped network path. The pool must validate on checkout instead.

NEON_IDLE_CUTOFF_S = 300  # Neon's approximate idle-connection cutoff


def build_pool_config() -> dict:
    """psycopg_pool settings for the episodic-memory PostgresStore."""
    from psycopg_pool import ConnectionPool

    return {
        "min_size": 1,
        "max_size": 3,
        # Validate (and transparently replace) a connection on checkout. This is
        # the fix: without it a server-closed connection is handed to synthesis.
        "check": ConnectionPool.check_connection,
        # Retire idle connections before Neon does it for us.
        "max_idle": 120,
        # Hard ceiling well inside a single report run (~10 min).
        "max_lifetime": 600,
        "reconnect_timeout": 30.0,
        "kwargs": {
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5,
        },
    }


def save_episodic_memory(store: BaseStore, domain_results: list[dict[str, Any]]) -> None:
    """Extract and persist episodic facts from domain results into the Store."""
    today = date.today().isoformat()

    # ── 1. Repeat offender IPs ────────────────────────────────────────────────
    # Collect unique external IPs with their source domains (dedup within a run)
    ip_domains: dict[str, set[str]] = {}
    for dr in domain_results:
        for ip_str in dr.get("flagged_ips", []):
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.is_private or addr.is_multicast or addr.is_reserved or addr.is_loopback:
                    continue
            except ValueError:
                continue
            ip_domains.setdefault(ip_str, set()).add(dr["domain"])

    for ip_str, domains in ip_domains.items():
        existing = store.get(_NS_IPS, ip_str)
        if existing:
            val = existing.value
            # Only increment count if this is a new day
            if val.get("last_seen") != today:
                val["count"] = val.get("count", 1) + 1
            val["last_seen"] = today
            val["domains"] = list(set(val.get("domains", [])) | domains)
        else:
            val = {
                "count": 1,
                "first_seen": today,
                "last_seen": today,
                "domains": sorted(domains),
            }
        store.put(_NS_IPS, ip_str, val)

    # ── 2. Severity trends ────────────────────────────────────────────────────
    for dr in domain_results:
        domain = dr["domain"]
        existing = store.get(_NS_SEVERITY, domain)
        history = existing.value.get("history", []) if existing else []
        history.append({"date": today, "severity": dr.get("overall_severity", "ok")})
        history = history[-_MAX_HISTORY:]
        store.put(_NS_SEVERITY, domain, {"history": history})

    # ── 3. Finding count trends ───────────────────────────────────────────────
    for dr in domain_results:
        domain = dr["domain"]
        findings = dr.get("findings", [])
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        warning = sum(1 for f in findings if f.get("severity") == "warning")
        existing = store.get(_NS_FINDINGS, domain)
        history = existing.value.get("history", []) if existing else []
        history.append({"date": today, "critical": critical, "warning": warning})
        history = history[-_MAX_HISTORY:]
        store.put(_NS_FINDINGS, domain, {"history": history})

    logger.info("Episodic memory saved for %d domain results", len(domain_results))


def format_episodic_context(store: BaseStore) -> str:
    """Load episodic memory from the Store and format for the synthesis prompt.

    Returns empty string if nothing noteworthy (first run, or no patterns).
    Output target: under 500 chars.
    """
    sections: list[str] = []

    # ── Repeat offenders (IPs seen >= 2 days) ─────────────────────────────────
    try:
        ip_items = store.search(_NS_IPS, limit=50)
        repeat_ips = [
            (item.key, item.value)
            for item in ip_items
            if item.value.get("count", 0) >= 2
        ]
        repeat_ips.sort(key=lambda x: x[1]["count"], reverse=True)
        if repeat_ips:
            parts = [
                f"{ip} ({v['count']} days, {'+'.join(v['domains'])})"
                for ip, v in repeat_ips[:3]
            ]
            sections.append(f"  Repeat offenders: {', '.join(parts)}")
    except Exception as e:
        logger.warning("Failed to load repeat offender IPs: %s", e)

    # ── Severity trends (non-ok streaks >= 2 days) ────────────────────────────
    try:
        severity_items = store.search(_NS_SEVERITY, limit=20)
        for item in severity_items:
            history = item.value.get("history", [])
            if len(history) >= 2:
                recent = [h["severity"] for h in history[-3:]]
                if all(s in ("warning", "critical") for s in recent):
                    sections.append(
                        f"  Severity trends: {item.key} {recent[-1]} {len(recent)} days running"
                    )
    except Exception as e:
        logger.warning("Failed to load severity trends: %s", e)

    # ── Finding escalation (rising critical counts) ───────────────────────────
    try:
        finding_items = store.search(_NS_FINDINGS, limit=20)
        for item in finding_items:
            history = item.value.get("history", [])
            if len(history) >= 2:
                crits = [h["critical"] for h in history[-3:]]
                if len(crits) >= 2 and crits[-1] > crits[0] and crits[-1] > 0:
                    trend = "\u2192".join(str(c) for c in crits)
                    sections.append(
                        f"  Finding escalation: {item.key} critical {trend}"
                    )
    except Exception as e:
        logger.warning("Failed to load finding trends: %s", e)

    if not sections:
        return ""

    # Cap at 3 items total to stay under 500 chars
    sections = sections[:3]
    return "Cross-run memory (last 7 days):\n" + "\n".join(sections)
