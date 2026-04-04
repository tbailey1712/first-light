"""
Cloudflare security tools — queries WAF events, Zero Trust Gateway DNS blocks,
and zone traffic analytics via the Cloudflare GraphQL Analytics API.

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
_CF_API = "https://api.cloudflare.com/client/v4"


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
    """Return (from_iso, to_iso) for the last N hours in UTC."""
    to_dt = datetime.now(timezone.utc)
    from_dt = to_dt - timedelta(hours=hours)
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
    """Get Cloudflare WAF and firewall events for the last N hours.

    Covers: WAF rule blocks, rate limit bans, managed rules, custom rules,
    DDoS mitigation actions, bot management challenges.

    Args:
        hours: Lookback window in hours (default: 24)

    Returns:
        JSON with action breakdown, top blocked IPs, countries, and rule IDs.
    """
    cfg = get_config()
    headers = _cf_headers()
    if not headers:
        return json.dumps({"error": "CLOUDFLARE_API_TOKEN not set"})

    zone_id = getattr(cfg, "cloudflare_zone_id", None)
    if not zone_id:
        return json.dumps({"error": "CLOUDFLARE_ZONE_ID not set"})

    from_ts, to_ts = _time_range(hours)

    # Aggregated WAF events grouped by action + source + country
    query = """
query WafEventsGrouped(
  $zoneTag: String!
  $from: Time!
  $to: Time!
) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      actionGroups: firewallEventsAdaptiveGroups(
        limit: 100
        filter: { datetime_geq: $from, datetime_leq: $to }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          action
          source
          clientCountryName
          ruleId
        }
      }
      topIPs: firewallEventsAdaptiveGroups(
        limit: 20
        filter: { datetime_geq: $from, datetime_leq: $to, action_neq: "allow" }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientIP
          clientCountryName
          action
          clientRequestHTTPHost
          userAgent
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
        return json.dumps({"error": f"Cloudflare WAF GraphQL failed: {e}"})

    errors = data.get("errors")
    if errors:
        return json.dumps({"error": f"GraphQL errors: {errors}"})

    zones_data = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones_data:
        return json.dumps({"waf_events": [], "top_ips": [], "total_events": 0})

    zone = zones_data[0]
    action_groups = zone.get("actionGroups", [])
    top_ips = zone.get("topIPs", [])

    # Aggregate by action
    action_summary: dict = {}
    by_source: dict = {}
    by_country: dict = {}
    total = 0

    for group in action_groups:
        cnt = group["count"]
        total += cnt
        dims = group["dimensions"]
        action = dims.get("action", "unknown")
        source = dims.get("source", "unknown")
        country = dims.get("clientCountryName", "unknown")

        action_summary[action] = action_summary.get(action, 0) + cnt
        by_source[source] = by_source.get(source, 0) + cnt
        by_country[country] = by_country.get(country, 0) + cnt

    # Top blocked IPs (exclude action=allow)
    blocked_ips = []
    for group in top_ips:
        dims = group["dimensions"]
        if dims.get("action") == "allow":
            continue
        blocked_ips.append({
            "ip": dims.get("clientIP"),
            "country": dims.get("clientCountryName"),
            "action": dims.get("action"),
            "host": dims.get("clientRequestHTTPHost"),
            "count": group["count"],
        })

    # Top countries (non-allow)
    top_countries = sorted(by_country.items(), key=lambda x: x[1], reverse=True)[:10]

    return json.dumps({
        "period_hours": hours,
        "total_security_events": total,
        "by_action": action_summary,
        "by_source": {k: v for k, v in sorted(by_source.items(), key=lambda x: x[1], reverse=True)},
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
        "top_blocked_ips": blocked_ips[:15],
    }, indent=2)


@tool
def query_cloudflare_gateway_dns(hours: int = 24) -> str:
    """Get Cloudflare Zero Trust Gateway DNS activity for the last N hours.

    Shows blocked domains, policy decisions, and top DNS query patterns from
    Cloudflare's DNS-over-HTTPS Gateway (the external DNS filter layer).

    Args:
        hours: Lookback window in hours (default: 24)

    Returns:
        JSON with blocked domains, policy decisions, and query stats.
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
query GatewayDns(
  $accountTag: String!
  $from: Time!
  $to: Time!
) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      topDomains: gatewayResolverQueriesAdaptiveGroups(
        limit: 100
        filter: {
          datetime_geq: $from
          datetime_leq: $to
        }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          queryName
          policyDecision
          policyName
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
        # Gateway analytics may require Zero Trust plan — surface helpful error
        error_msgs = [e.get("message", str(e)) for e in errors]
        return json.dumps({
            "error": f"Gateway DNS GraphQL errors (check Zero Trust plan + token permissions): {error_msgs}"
        })

    accounts_data = data.get("data", {}).get("viewer", {}).get("accounts", [])
    if not accounts_data:
        return json.dumps({"blocked_domains": [], "decision_summary": {}, "total_queries": 0})

    acct = accounts_data[0]

    # Split by decision from single query
    decisions: dict = {}
    blocked = []
    allowed_top = []

    for group in acct.get("topDomains", []):
        dims = group["dimensions"]
        decision = dims.get("policyDecision", "unknown")
        cnt = group["count"]
        decisions[decision] = decisions.get(decision, 0) + cnt

        if decision == "block":
            blocked.append({
                "domain": dims.get("queryName"),
                "policy": dims.get("policyName"),
                "decision": decision,
                "count": cnt,
            })
        elif decision == "allow" and len(allowed_top) < 10:
            allowed_top.append({
                "domain": dims.get("queryName"),
                "count": cnt,
            })

    total = sum(decisions.values())
    blocked.sort(key=lambda x: x["count"], reverse=True)

    return json.dumps({
        "period_hours": hours,
        "total_queries": total,
        "decision_summary": decisions,
        "block_rate_pct": round(decisions.get("block", 0) / total * 100, 2) if total else 0,
        "top_blocked_domains": blocked[:20],
        "top_allowed_domains": allowed_top,
    }, indent=2)


@tool
def query_cloudflare_zone_analytics(hours: int = 24) -> str:
    """Get Cloudflare zone-level traffic analytics for the last N hours.

    Shows overall request volume, threats mitigated, bot traffic percentage,
    cache performance, and bandwidth served vs origin.

    Args:
        hours: Lookback window in hours (default: 24)

    Returns:
        JSON with traffic totals, threat breakdown, and cache stats.
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
query ZoneAnalytics(
  $zoneTag: String!
  $from: Time!
  $to: Time!
) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      requests: httpRequestsAdaptiveGroups(
        limit: 10
        filter: { datetime_geq: $from, datetime_leq: $to }
        orderBy: [count_DESC]
      ) {
        count
        sum {
          bytes
          cachedRequests
        }
        dimensions {
          cacheStatus
        }
      }
      threats: httpRequestsAdaptiveGroups(
        limit: 20
        filter: {
          datetime_geq: $from
          datetime_leq: $to
          securityLevel_neq: "off"
        }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          securityLevel
          clientCountryName
        }
      }
      topPaths: httpRequestsAdaptiveGroups(
        limit: 10
        filter: { datetime_geq: $from, datetime_leq: $to }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientRequestPath
          edgeResponseStatus
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
        error_msgs = [e.get("message", str(e)) for e in errors]
        return json.dumps({"error": f"Zone analytics GraphQL errors: {error_msgs}"})

    zones_data = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones_data:
        return json.dumps({"total_requests": 0, "threats": {}, "cache": {}})

    zone = zones_data[0]

    # Request totals and cache stats
    total_requests = 0
    total_bytes = 0
    cached_bytes = 0
    cache_by_status: dict = {}

    total_cached_requests = 0
    for group in zone.get("requests", []):
        cnt = group["count"]
        total_requests += cnt
        sums = group.get("sum") or {}
        total_bytes += sums.get("bytes") or 0
        total_cached_requests += sums.get("cachedRequests") or 0
        status = group["dimensions"].get("cacheStatus", "unknown")
        cache_by_status[status] = cache_by_status.get(status, 0) + cnt

    cache_hit_pct = round(total_cached_requests / total_requests * 100, 1) if total_requests else 0

    # Threat/security breakdown
    threat_summary: dict = {}
    by_country: dict = {}
    for group in zone.get("threats", []):
        cnt = group["count"]
        level = group["dimensions"].get("securityLevel", "unknown")
        country = group["dimensions"].get("clientCountryName", "unknown")
        if level not in ("off", "essentially_off"):
            threat_summary[level] = threat_summary.get(level, 0) + cnt
            by_country[country] = by_country.get(country, 0) + cnt

    top_threat_countries = sorted(by_country.items(), key=lambda x: x[1], reverse=True)[:8]

    # Top paths (4xx/5xx indicate scanning or attack surface issues)
    top_paths = []
    for group in zone.get("topPaths", [])[:10]:
        dims = group["dimensions"]
        status = dims.get("edgeResponseStatus", 0)
        top_paths.append({
            "path": dims.get("clientRequestPath"),
            "status": status,
            "count": group["count"],
            "anomalous": status in (400, 403, 404, 429, 500, 502, 503),
        })

    return json.dumps({
        "period_hours": hours,
        "total_requests": total_requests,
        "total_bytes_gb": round(total_bytes / 1e9, 3),
        "cache_hit_pct": cache_hit_pct,
        "cache_by_status": cache_by_status,
        "security_events": threat_summary,
        "threat_countries": [{"country": c, "count": n} for c, n in top_threat_countries],
        "top_paths": top_paths,
    }, indent=2)
