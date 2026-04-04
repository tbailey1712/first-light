"""
Cloudflare security tools — queries WAF events, Zero Trust Gateway DNS blocks,
and zone traffic analytics via the Cloudflare GraphQL Analytics API.

Confirmed-working GraphQL datasets (tested against live CF account):
  - firewallEventsAdaptive (individual events, max 500/query)
  - gatewayResolverQueriesAdaptiveGroups (resolverDecision: 9=block, 5=allow/no-policy, 10=explicit-allow)
  - httpRequestsAdaptiveGroups (count + dimensions only, no sum block needed)

Required env vars:
  CLOUDFLARE_API_TOKEN   — API token with Zone:Analytics:Read + Zone:Firewall:Read
                           + Account:Zero Trust:Read (for Gateway DNS)
  CLOUDFLARE_ZONE_ID     — Zone ID for mcducklabs.com (found in Cloudflare dashboard)
  CLOUDFLARE_ACCOUNT_ID  — Account ID (found in Cloudflare dashboard Overview)
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)

_CF_GRAPHQL = "https://api.cloudflare.com/client/v4/graphql"

# resolverDecision codes for gatewayResolverQueriesAdaptiveGroups
_GATEWAY_DECISIONS = {
    5: "allowed_no_policy",   # no policy matched, allowed by default
    9: "blocked",             # blocked by a Gateway policy
    10: "allowed_by_policy",  # explicitly allowed by a rule
}


def _cf_headers() -> Optional[dict]:
    """Return CF API headers, or None if token is not configured."""
    cfg = get_config()
    token = getattr(cfg, "cloudflare_api_token", None)
    if not token:
        return None
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _time_range(hours: int) -> tuple[str, str]:
    """Return (from_iso, to_iso) for the last N hours in UTC.

    Note: Cloudflare GraphQL enforces a 1-day max range on free/pro plans.
    We cap at 23h to stay safely within limit.
    """
    to_dt = datetime.now(timezone.utc)
    effective_hours = min(hours, 23)
    from_dt = to_dt - timedelta(hours=effective_hours)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return from_dt.strftime(fmt), to_dt.strftime(fmt)


def _graphql(query: str, variables: dict, headers: dict) -> dict:
    """Execute a Cloudflare GraphQL query. Raises on HTTP error."""
    with httpx.Client(timeout=20.0) as client:
        resp = client.post(
            _CF_GRAPHQL,
            headers=headers,
            json={"query": query, "variables": variables},
        )
        resp.raise_for_status()
        return resp.json()


@tool
def query_cloudflare_waf_events(hours: int = 24) -> str:
    """Get Cloudflare WAF and firewall events for mcducklabs.com in the last N hours.

    Covers: WAF rule blocks, managed rules, custom rules, rate limit bans.
    These are requests stopped at Cloudflare's edge before reaching origin.

    Args:
        hours: Lookback window in hours (default: 24, capped at 23h by CF plan limit)

    Returns:
        JSON with total events, action breakdown, top countries, top blocked IPs, rule sources.
    """
    cfg = get_config()
    headers = _cf_headers()
    if not headers:
        return json.dumps({"error": "CLOUDFLARE_API_TOKEN not set"})

    zone_id = getattr(cfg, "cloudflare_zone_id", None)
    if not zone_id:
        return json.dumps({"error": "CLOUDFLARE_ZONE_ID not set"})

    from_ts, to_ts = _time_range(hours)

    # firewallEventsAdaptive returns individual events (not grouped).
    # firewallEventsAdaptiveGroups requires Business/Enterprise plan.
    # We fetch up to 500 individual events and aggregate in Python.
    query = """
query WafEvents($zoneTag: String!, $from: Time!, $to: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(
        limit: 500
        filter: { datetime_geq: $from, datetime_leq: $to }
        orderBy: [datetime_DESC]
      ) {
        action
        source
        clientIP
        clientCountryName
        ruleId
      }
    }
  }
}
"""
    try:
        data = _graphql(
            query,
            {"zoneTag": zone_id, "from": from_ts, "to": to_ts},
            headers,
        )
    except Exception as e:
        return json.dumps({"error": f"Cloudflare WAF GraphQL failed: {e}"})

    errors = data.get("errors")
    if errors:
        return json.dumps({"error": f"GraphQL errors: {[e.get('message') for e in errors]}"})

    zones_data = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones_data:
        return json.dumps({"total_events": 0, "by_action": {}, "by_source": {}, "top_countries": [], "top_ips": []})

    events = zones_data[0].get("firewallEventsAdaptive", [])

    # Aggregate
    by_action: dict = {}
    by_source: dict = {}
    by_country: dict = {}
    ip_counts: dict = {}

    for e in events:
        action = e.get("action", "unknown")
        source = e.get("source", "unknown")
        country = e.get("clientCountryName", "unknown")
        ip = e.get("clientIP", "unknown")

        by_action[action] = by_action.get(action, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1
        by_country[country] = by_country.get(country, 0) + 1
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    top_countries = sorted(by_country.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Add country to top IPs
    ip_country = {e.get("clientIP"): e.get("clientCountryName") for e in events}
    top_ips_detail = [
        {"ip": ip, "count": cnt, "country": ip_country.get(ip)}
        for ip, cnt in top_ips
    ]

    note = ""
    if len(events) == 500:
        note = "Result capped at 500 events — actual count may be higher"

    return json.dumps({
        "period_hours": min(hours, 23),
        "total_events": len(events),
        "note": note,
        "by_action": {k: v for k, v in sorted(by_action.items(), key=lambda x: x[1], reverse=True)},
        "by_source": {k: v for k, v in sorted(by_source.items(), key=lambda x: x[1], reverse=True)},
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
        "top_ips": top_ips_detail,
    }, indent=2)


@tool
def query_cloudflare_gateway_dns(hours: int = 24) -> str:
    """Get Cloudflare Zero Trust Gateway DNS activity for the last N hours.

    Gateway is the external DNS-over-HTTPS filter — external vantage point
    complementing AdGuard (internal). Shows what Cloudflare is blocking for
    devices using the Gateway resolver.

    resolverDecision codes: 9=blocked by policy, 5=allowed (no policy matched),
    10=allowed by explicit policy rule.

    Args:
        hours: Lookback window in hours (default: 24, capped at 23h)

    Returns:
        JSON with query totals, decision breakdown, top blocked domains and policies.
    """
    cfg = get_config()
    headers = _cf_headers()
    if not headers:
        return json.dumps({"error": "CLOUDFLARE_API_TOKEN not set"})

    account_id = getattr(cfg, "cloudflare_account_id", None)
    if not account_id:
        return json.dumps({"error": "CLOUDFLARE_ACCOUNT_ID not set"})

    from_ts, to_ts = _time_range(hours)

    query = """
query GatewayDns($accountTag: String!, $from: Time!, $to: Time!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      gatewayResolverQueriesAdaptiveGroups(
        limit: 200
        filter: { datetime_geq: $from, datetime_leq: $to }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          queryName
          resolverDecision
          policyName
          policyId
        }
      }
    }
  }
}
"""
    try:
        data = _graphql(
            query,
            {"accountTag": account_id, "from": from_ts, "to": to_ts},
            headers,
        )
    except Exception as e:
        return json.dumps({"error": f"Cloudflare Gateway DNS GraphQL failed: {e}"})

    errors = data.get("errors")
    if errors:
        return json.dumps({
            "error": f"Gateway DNS errors: {[e.get('message') for e in errors]}"
        })

    accounts_data = data.get("data", {}).get("viewer", {}).get("accounts", [])
    if not accounts_data:
        return json.dumps({"total_queries": 0, "blocked": 0, "top_blocked_domains": []})

    rows = accounts_data[0].get("gatewayResolverQueriesAdaptiveGroups", [])

    # Aggregate by decision code
    decision_totals: dict = {}
    blocked_domains: list = []
    policy_counts: dict = {}
    total = 0

    for row in rows:
        dims = row["dimensions"]
        cnt = row["count"]
        total += cnt
        decision_code = dims.get("resolverDecision", 0)
        decision_label = _GATEWAY_DECISIONS.get(decision_code, f"code_{decision_code}")
        decision_totals[decision_label] = decision_totals.get(decision_label, 0) + cnt

        if decision_code == 9:  # blocked
            policy = dims.get("policyName") or "unknown policy"
            blocked_domains.append({
                "domain": dims.get("queryName"),
                "policy": policy,
                "count": cnt,
            })
            policy_counts[policy] = policy_counts.get(policy, 0) + cnt

    blocked_total = decision_totals.get("blocked", 0)
    block_rate = round(blocked_total / total * 100, 2) if total else 0

    return json.dumps({
        "period_hours": min(hours, 23),
        "total_queries": total,
        "decision_breakdown": decision_totals,
        "blocked_total": blocked_total,
        "block_rate_pct": block_rate,
        "blocks_by_policy": {k: v for k, v in sorted(policy_counts.items(), key=lambda x: x[1], reverse=True)},
        "top_blocked_domains": sorted(blocked_domains, key=lambda x: x["count"], reverse=True)[:20],
    }, indent=2)


@tool
def query_cloudflare_zone_analytics(hours: int = 24) -> str:
    """Get Cloudflare zone-level traffic analytics for mcducklabs.com in the last N hours.

    Shows overall request volume, response status distribution, cache performance,
    and top requesting countries.

    Args:
        hours: Lookback window in hours (default: 24, capped at 23h)

    Returns:
        JSON with request totals, status code distribution, cache stats, top countries.
    """
    cfg = get_config()
    headers = _cf_headers()
    if not headers:
        return json.dumps({"error": "CLOUDFLARE_API_TOKEN not set"})

    zone_id = getattr(cfg, "cloudflare_zone_id", None)
    if not zone_id:
        return json.dumps({"error": "CLOUDFLARE_ZONE_ID not set"})

    from_ts, to_ts = _time_range(hours)

    query = """
query ZoneAnalytics($zoneTag: String!, $from: Time!, $to: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      byStatus: httpRequestsAdaptiveGroups(
        limit: 50
        filter: { datetime_geq: $from, datetime_leq: $to }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          edgeResponseStatus
          cacheStatus
        }
      }
      byCountry: httpRequestsAdaptiveGroups(
        limit: 20
        filter: { datetime_geq: $from, datetime_leq: $to }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientCountryName
        }
      }
    }
  }
}
"""
    try:
        data = _graphql(
            query,
            {"zoneTag": zone_id, "from": from_ts, "to": to_ts},
            headers,
        )
    except Exception as e:
        return json.dumps({"error": f"Cloudflare zone analytics GraphQL failed: {e}"})

    errors = data.get("errors")
    if errors:
        return json.dumps({"error": f"Zone analytics errors: {[e.get('message') for e in errors]}"})

    zones_data = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones_data:
        return json.dumps({"total_requests": 0})

    zone = zones_data[0]

    # Request totals and status distribution
    total_requests = 0
    by_status: dict = {}
    by_cache: dict = {}

    for group in zone.get("byStatus", []):
        cnt = group["count"]
        total_requests += cnt
        status = group["dimensions"].get("edgeResponseStatus", 0)
        cache = group["dimensions"].get("cacheStatus", "unknown")
        status_class = f"{status // 100}xx" if status else "unknown"
        by_status[status_class] = by_status.get(status_class, 0) + cnt
        by_cache[cache] = by_cache.get(cache, 0) + cnt

    # Top countries
    country_counts: dict = {}
    for group in zone.get("byCountry", []):
        country = group["dimensions"].get("clientCountryName", "unknown")
        country_counts[country] = country_counts.get(country, 0) + group["count"]

    top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Flag anomalous status codes
    error_requests = by_status.get("4xx", 0) + by_status.get("5xx", 0)
    error_rate = round(error_requests / total_requests * 100, 1) if total_requests else 0

    return json.dumps({
        "period_hours": min(hours, 23),
        "total_requests": total_requests,
        "by_status_class": {k: v for k, v in sorted(by_status.items(), key=lambda x: x[1], reverse=True)},
        "error_requests": error_requests,
        "error_rate_pct": error_rate,
        "cache_by_status": by_cache,
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
    }, indent=2)
