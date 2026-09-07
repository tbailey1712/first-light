"""
Tools for querying the AdGuard Home query log directly.

Why this exists: the `query_adguard_*` tools in metrics.py read the AdGuard
*exporter's* metrics out of ClickHouse. Those give aggregate shape -- query
counts, block rates, a per-client TXT ratio -- but never a domain name. So the
daily report could flag "openwebui TXT ratio 47.74, investigate" and then had
no way to investigate it. These tools close that loop by naming the domains.

Auth: AdGuard Home uses HTTP Basic auth on /control/*. It answers 401 without
credentials, so `adguard_username` / `adguard_password` must be set.

Network: AdGuard sits on VLAN 1 and the agent runs on VLAN 2, so this requires
a firewall rule permitting the Docker host to reach AdGuard's web port. Without
it every call fails with a connect error, not an auth error -- the two are
distinguished in the returned payload so the agent can tell them apart.
"""

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

# AdGuard returns newest-first. This caps how many records we pull per call;
# a busy client can generate thousands of queries an hour.
_DEFAULT_FETCH = 1000
_MAX_FETCH = 5000


def _adguard_base() -> Optional[str]:
    cfg = get_config()
    if not cfg.adguard_host:
        return None
    return f"http://{cfg.adguard_host}:{cfg.adguard_port}"


def _adguard_get(path: str, params: Optional[dict] = None) -> dict:
    """Authenticated GET against AdGuard Home. Returns parsed JSON or {"error": ...}."""
    cfg = get_config()
    base = _adguard_base()
    if not base:
        return {"error": "adguard_host not configured in .env"}
    if not cfg.adguard_username:
        return {"error": "adguard_username/adguard_password not configured in .env"}

    try:
        with httpx.Client(timeout=20.0) as client:
            r = client.get(
                f"{base}{path}",
                params=params,
                auth=(cfg.adguard_username, cfg.adguard_password or ""),
            )
    except Exception as e:
        # Connectivity failure is a different problem from auth failure, and the
        # fix is different too (firewall rule vs credentials). Keep them distinct.
        return {"error": f"connect failed: {e}", "hint": "check VLAN 2 -> VLAN 1 firewall rule"}

    if r.status_code == 401:
        return {"error": "HTTP 401 unauthorized", "hint": "check adguard_username/password"}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}", "body": r.text[:200]}
    try:
        return r.json()
    except Exception as e:
        return {"error": f"bad JSON from AdGuard: {e}"}


def _parse_time(value: str) -> Optional[datetime]:
    """AdGuard timestamps are RFC3339, sometimes with more than 6 fractional digits."""
    if not value:
        return None
    v = value.replace("Z", "+00:00")
    if "." in v:
        head, _, tail = v.partition(".")
        digits = "".join(c for c in tail if c.isdigit())[:6]
        offset = tail[len(tail.rstrip("0123456789")) * 0:]
        tz = ""
        for marker in ("+", "-"):
            if marker in tail:
                tz = tail[tail.index(marker):]
                break
        v = f"{head}.{digits or '0'}{tz}"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _collect(client_ip: str, hours: int, fetch: int) -> tuple[list[dict], Optional[dict]]:
    """Fetch query-log rows for one client within the window. Returns (rows, error)."""
    payload = _adguard_get(
        "/control/querylog",
        {"limit": min(max(fetch, 1), _MAX_FETCH), "search": client_ip, "response_status": "all"},
    )
    if "error" in payload:
        return [], payload

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = []
    for entry in payload.get("data") or []:
        # `search` matches domains as well as clients, so filter explicitly.
        if entry.get("client") != client_ip:
            continue
        ts = _parse_time(entry.get("time", ""))
        if ts and ts < cutoff:
            continue
        rows.append(entry)
    return rows, None


@tool
def query_adguard_client_domains(
    client_ip: str,
    query_type: str = "",
    hours: int = 24,
    limit: int = 25,
) -> str:
    """Get the actual domains a client is querying, from the AdGuard Home query log.

    Use this to explain a DNS finding rather than just report it -- for example
    when a client shows a high TXT ratio, call this with query_type="TXT" to see
    which names it is actually asking for.

    Args:
        client_ip: Client IP, e.g. "192.168.2.15"
        query_type: Filter to one record type (A, AAAA, TXT, SRV, PTR...). Empty = all.
        hours: Look-back window in hours (default 24)
        limit: Number of distinct domains to return (default 25)

    Returns:
        JSON with the query-type breakdown and the top domains with per-domain counts.
    """
    rows, err = _collect(client_ip, hours, _DEFAULT_FETCH)
    if err:
        return json.dumps(err)

    wanted = query_type.strip().upper()
    types = Counter((r.get("question") or {}).get("type", "?") for r in rows)
    if wanted:
        rows = [r for r in rows if ((r.get("question") or {}).get("type", "")).upper() == wanted]

    domains = Counter((r.get("question") or {}).get("name", "?") for r in rows)
    blocked = sum(
        1 for r in rows if str(r.get("reason", "")).lower().startswith("filtered")
    )

    return json.dumps({
        "client_ip": client_ip,
        "hours": hours,
        "query_type_filter": wanted or "all",
        "records_examined": sum(types.values()),
        "records_matching": len(rows),
        "blocked": blocked,
        "query_type_breakdown": dict(types.most_common()),
        "top_domains": [{"domain": d, "count": c} for d, c in domains.most_common(limit)],
    }, indent=2)


@tool
def query_adguard_txt_offenders(hours: int = 24, limit: int = 10) -> str:
    """Explain a high TXT ratio: show the TXT domains queried across all clients.

    The exporter publishes a per-client TXT ratio but no domain detail, so a
    "TXT ratio 47.74" finding is unactionable on its own. This returns the TXT
    records actually being asked for, grouped by client.

    Args:
        hours: Look-back window in hours (default 24)
        limit: Number of distinct domains to return per client (default 10)

    Returns:
        JSON mapping each client that issued TXT queries to its top TXT domains.
    """
    payload = _adguard_get(
        "/control/querylog",
        {"limit": _MAX_FETCH, "response_status": "all"},
    )
    if "error" in payload:
        return json.dumps(payload)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    per_client: dict[str, Counter] = {}
    for entry in payload.get("data") or []:
        q = entry.get("question") or {}
        if str(q.get("type", "")).upper() != "TXT":
            continue
        ts = _parse_time(entry.get("time", ""))
        if ts and ts < cutoff:
            continue
        per_client.setdefault(entry.get("client", "?"), Counter())[q.get("name", "?")] += 1

    return json.dumps({
        "hours": hours,
        "clients_with_txt": len(per_client),
        "clients": {
            ip: {
                "txt_queries": sum(c.values()),
                "top_domains": [{"domain": d, "count": n} for d, n in c.most_common(limit)],
            }
            for ip, c in sorted(per_client.items(), key=lambda kv: -sum(kv[1].values()))
        },
    }, indent=2)
