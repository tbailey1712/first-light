"""
AdGuard Home direct API tools — per-client query log investigation.

These tools call the AdGuard Home REST API directly (not the Prometheus metrics
exporter). They require live API credentials and return real-time data from the
AdGuard query log.

.env vars required:
  ADGUARD_HOST      IP or hostname of AdGuard Home (e.g. adguard.mcducklabs.com)
  ADGUARD_PORT      Port (default: 3000)
  ADGUARD_USERNAME  AdGuard admin username
  ADGUARD_PASSWORD  AdGuard admin password

API base: http://{host}:{port}/control/
All endpoints use HTTP Basic auth.
"""

import json
import logging
from collections import Counter
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)


def _adguard_get(path: str, params: Optional[dict] = None) -> dict | list | str:
    """Authenticated GET against AdGuard Home REST API.

    Returns parsed JSON body, or a dict with 'error' key on failure.
    """
    cfg = get_config()
    host = getattr(cfg, "adguard_host", None)
    if not host:
        return {"error": "ADGUARD_HOST not configured in .env"}

    port = getattr(cfg, "adguard_port", 3000) or 3000
    username = getattr(cfg, "adguard_username", None)
    password = getattr(cfg, "adguard_password", None)

    if not username or not password:
        return {"error": "ADGUARD_USERNAME or ADGUARD_PASSWORD not configured in .env"}

    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/control/{path.lstrip('/')}"
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(url, params=params or {}, auth=(username, password))
            if resp.status_code == 401:
                return {"error": "AdGuard authentication failed — check ADGUARD_USERNAME/PASSWORD"}
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            return resp.json()
    except Exception as e:
        logger.error("AdGuard API request failed: %s", e)
        return {"error": str(e)}


# ── Tools ──────────────────────────────────────────────────────────────────────

@tool
def query_adguard_client_blocked_domains(
    client_ip: str,
    limit: int = 200,
) -> str:
    """Get top blocked domains for a specific client IP from AdGuard query log.

    Useful for investigating high-risk clients (e.g. a device with 100% block
    rate), identifying what they're trying to reach, and deciding whether to
    allow or further restrict the client.

    Args:
        client_ip: Client IP address to query (e.g. "192.168.1.42")
        limit: Max query log entries to scan (default: 200, max: 1000)

    Returns:
        JSON with client IP, total blocked queries, and top blocked domains with
        counts and the reason each was blocked.
    """
    cfg = get_config()
    if not getattr(cfg, "adguard_host", None):
        return json.dumps({"error": "ADGUARD_HOST not configured in .env"})

    # AdGuard query log endpoint: GET /control/querylog
    # Supports: client_id (IP or name), response_status, limit, offset
    limit = min(limit, 1000)
    data = _adguard_get("querylog", {
        "client_id": client_ip,
        "response_status": "filtered",
        "limit": limit,
    })

    if isinstance(data, dict) and "error" in data:
        return json.dumps(data)

    entries = []
    if isinstance(data, dict):
        entries = data.get("data", [])
    elif isinstance(data, list):
        entries = data

    domain_counts: Counter = Counter()
    reason_by_domain: dict = {}

    for entry in entries:
        question = entry.get("question", {})
        domain = question.get("name", "").rstrip(".")
        if not domain:
            continue
        domain_counts[domain] += 1
        if domain not in reason_by_domain:
            # result.reason is the block reason (FilteredBlacklist, FilteredParentalControl, etc.)
            result = entry.get("result", {})
            reason_by_domain[domain] = result.get("reason", "filtered")

    top_domains = [
        {"domain": domain, "count": count, "reason": reason_by_domain.get(domain, "")}
        for domain, count in domain_counts.most_common(50)
    ]

    return json.dumps({
        "client_ip": client_ip,
        "total_blocked": len(entries),
        "unique_domains_blocked": len(domain_counts),
        "top_blocked_domains": top_domains,
    }, indent=2)


@tool
def query_adguard_nxdomain_clients(
    limit: int = 500,
    top_n: int = 20,
) -> str:
    """Get per-client NXDomain rates from AdGuard query log.

    NXDomain spikes per client are a reliable signal for DGA malware or
    misconfigured applications making random domain lookups.

    Scans recent query log entries with NXDOMAIN responses and computes:
    - Which clients are generating the most NXDomain responses
    - Which domains are returning NXDOMAIN most frequently per client

    Args:
        limit: Query log entries to scan (default: 500, max: 2000)
        top_n: Number of top clients/domains to return (default: 20)

    Returns:
        JSON with per-client NXDomain counts and top NXDomain domains.
    """
    cfg = get_config()
    if not getattr(cfg, "adguard_host", None):
        return json.dumps({"error": "ADGUARD_HOST not configured in .env"})

    limit = min(limit, 2000)
    data = _adguard_get("querylog", {
        "response_status": "processed",
        "limit": limit,
    })

    if isinstance(data, dict) and "error" in data:
        return json.dumps(data)

    entries = []
    if isinstance(data, dict):
        entries = data.get("data", [])
    elif isinstance(data, list):
        entries = data

    # Filter to NXDOMAIN responses — answer[0].type = "NXDOMAIN" or upstream returns NXDOMAIN
    client_nxdomain: Counter = Counter()
    domain_nxdomain: Counter = Counter()
    client_domains: dict = {}  # client_ip -> Counter of domains

    for entry in entries:
        # Check if this is an NXDOMAIN — AdGuard marks these in the answer section
        answer = entry.get("answer", [])
        is_nxdomain = False
        for a in answer:
            if a.get("type") == "NXDOMAIN":
                is_nxdomain = True
                break
        # Also check upstream_time_ns + no answer entries = possible NXDOMAIN
        if not is_nxdomain and not answer and entry.get("upstream"):
            # If upstream responded but no answer, likely NXDOMAIN
            # Check the result reason
            result = entry.get("result", {})
            if "NXDOMAIN" in str(result.get("reason", "")).upper():
                is_nxdomain = True

        if not is_nxdomain:
            continue

        client = entry.get("client", "unknown")
        question = entry.get("question", {})
        domain = question.get("name", "").rstrip(".")

        client_nxdomain[client] += 1
        if domain:
            domain_nxdomain[domain] += 1
            client_domains.setdefault(client, Counter())[domain] += 1

    top_clients = []
    for client_ip, count in client_nxdomain.most_common(top_n):
        top_domains = [
            {"domain": d, "count": c}
            for d, c in client_domains.get(client_ip, Counter()).most_common(10)
        ]
        top_clients.append({
            "client_ip": client_ip,
            "nxdomain_count": count,
            "top_nxdomain_domains": top_domains,
        })

    return json.dumps({
        "entries_scanned": len(entries),
        "total_nxdomain": sum(client_nxdomain.values()),
        "top_clients_by_nxdomain": top_clients,
        "top_nxdomain_domains": [
            {"domain": d, "count": c}
            for d, c in domain_nxdomain.most_common(top_n)
        ],
    }, indent=2)


@tool
def query_adguard_custom_rules() -> str:
    """Read AdGuard Home custom filtering rules (allowlist and blocklist entries).

    Useful for verifying whether a domain is already blocked or allowed before
    recommending an action, and for auditing what manual rules have been added.

    Returns:
        JSON with rule count and the list of raw rule strings.
        Rules prefixed with '@@' are allowlist entries.
        Rules with '!' are comments.
    """
    cfg = get_config()
    if not getattr(cfg, "adguard_host", None):
        return json.dumps({"error": "ADGUARD_HOST not configured in .env"})

    data = _adguard_get("filtering/rules/list", {"url": ""})
    if isinstance(data, dict) and "error" in data:
        # Try the main filtering status endpoint instead
        data = _adguard_get("filtering/status")
        if isinstance(data, dict) and "error" in data:
            return json.dumps(data)

        # Extract user rules from filtering status
        user_rules = data.get("user_rules", [])
        return json.dumps({
            "total_custom_rules": len(user_rules),
            "allowlist_rules": [r for r in user_rules if r.startswith("@@")],
            "blocklist_rules": [r for r in user_rules if not r.startswith(("@@", "!", "#", " "))],
            "comment_rules": [r for r in user_rules if r.startswith(("!", "#"))],
            "raw_rules": user_rules,
        }, indent=2)

    # Direct rules list endpoint
    rules = data if isinstance(data, list) else data.get("rules", [])
    return json.dumps({
        "total_custom_rules": len(rules),
        "allowlist_rules": [r for r in rules if r.startswith("@@")],
        "blocklist_rules": [r for r in rules if not r.startswith(("@@", "!", "#", " "))],
        "raw_rules": rules,
    }, indent=2)
