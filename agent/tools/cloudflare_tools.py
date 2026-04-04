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
        clientRequestHTTPHost
        clientRequestPath
        userAgent
        clientASNDescription
        datetime
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
    by_host: dict = {}
    ip_info: dict = {}  # ip -> {count, country, asn, paths}
    path_counts: dict = {}
    ua_counts: dict = {}

    for e in events:
        action = e.get("action", "unknown")
        source = e.get("source", "unknown")
        country = e.get("clientCountryName", "unknown")
        ip = e.get("clientIP", "unknown")
        host = e.get("clientRequestHTTPHost", "unknown")
        path = e.get("clientRequestPath", "/")
        ua = e.get("userAgent", "")
        asn = e.get("clientASNDescription", "")

        by_action[action] = by_action.get(action, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1
        by_country[country] = by_country.get(country, 0) + 1
        by_host[host] = by_host.get(host, 0) + 1
        path_key = f"{host}{path}"
        path_counts[path_key] = path_counts.get(path_key, 0) + 1

        if ip not in ip_info:
            ip_info[ip] = {"count": 0, "country": country, "asn": asn, "paths": set(), "hosts": set()}
        ip_info[ip]["count"] += 1
        ip_info[ip]["paths"].add(path)
        ip_info[ip]["hosts"].add(host)

        # Classify UA
        ua_lower = ua.lower()
        if not ua:
            ua_class = "no_ua"
        elif any(x in ua_lower for x in ["python", "curl", "wget", "go-http", "java", "libwww", "zgrab", "masscan", "nuclei", "sqlmap"]):
            ua_class = "scanner"
        elif any(x in ua_lower for x in ["mozilla", "chrome", "safari", "firefox", "edge"]):
            ua_class = "browser_ua"  # may still be a bot
        else:
            ua_class = "other"
        ua_counts[ua_class] = ua_counts.get(ua_class, 0) + 1

    top_countries = sorted(by_country.items(), key=lambda x: x[1], reverse=True)[:10]
    top_hosts = sorted(by_host.items(), key=lambda x: x[1], reverse=True)[:10]
    top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ips = sorted(ip_info.items(), key=lambda x: x[1]["count"], reverse=True)[:10]

    top_ips_detail = [
        {
            "ip": ip,
            "count": info["count"],
            "country": info["country"],
            "asn": info["asn"],
            "targeted_hosts": list(info["hosts"]),
            "paths": list(info["paths"])[:5],
        }
        for ip, info in top_ips
    ]

    note = "Result capped at 500 events — actual count may be higher" if len(events) == 500 else ""

    return json.dumps({
        "period_hours": min(hours, 23),
        "total_events": len(events),
        "note": note,
        "by_action": {k: v for k, v in sorted(by_action.items(), key=lambda x: x[1], reverse=True)},
        "by_source": {k: v for k, v in sorted(by_source.items(), key=lambda x: x[1], reverse=True)},
        "ua_classification": ua_counts,
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
        "top_targeted_services": [{"host": h, "count": n} for h, n in top_hosts],
        "top_attacked_paths": [{"path": p, "count": n} for p, n in top_paths],
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

    # Two separate aliases with distinct dimension sets — prevents cross-product
    # double-counting that occurs when both dimensions are mixed in one query.
    query = """
query ZoneAnalytics($zoneTag: String!, $from: Time!, $to: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      byStatus: httpRequestsAdaptiveGroups(
        limit: 50
        filter: { datetime_geq: $from, datetime_leq: $to }
        orderBy: [count_DESC]
        groupBy: [edgeResponseStatus, cacheStatus]
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
        groupBy: [clientCountryName]
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


@tool
def query_cloudflare_dns_analytics(hours: int = 24) -> str:
    """Get authoritative DNS query analytics for mcducklabs.com in the last N hours.

    Shows which subdomains are being resolved externally — useful for detecting
    subdomain enumeration, reconnaissance, and identifying exposed services.
    All subdomains in the results are publicly resolvable via Cloudflare DNS.

    Args:
        hours: Lookback window in hours (default: 24, capped at 23h)

    Returns:
        JSON with top queried subdomains, query types, response codes.
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
query DnsAnalytics($zoneTag: String!, $from: Time!, $to: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      dnsAnalyticsAdaptiveGroups(
        limit: 200
        filter: { datetime_geq: $from, datetime_leq: $to }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          queryName
          queryType
          responseCode
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
        return json.dumps({"error": f"Cloudflare DNS analytics GraphQL failed: {e}"})

    errors = data.get("errors")
    if errors:
        return json.dumps({"error": f"DNS analytics errors: {[e.get('message') for e in errors]}"})

    zones_data = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones_data:
        return json.dumps({"total_queries": 0, "subdomains": []})

    rows = zones_data[0].get("dnsAnalyticsAdaptiveGroups", [])

    # Aggregate by subdomain
    by_name: dict = {}
    by_type: dict = {}
    nxdomain: list = []
    recon_indicators: list = []

    for row in rows:
        dims = row["dimensions"]
        name = dims.get("queryName", "")
        qtype = dims.get("queryType", "")
        rcode = dims.get("responseCode", "")
        cnt = row["count"]

        by_name[name] = by_name.get(name, 0) + cnt
        by_type[qtype] = by_type.get(qtype, 0) + cnt

        if rcode == "NXDOMAIN":
            nxdomain.append({"name": name, "type": qtype, "count": cnt})

        # Flag suspicious patterns
        name_lower = name.lower()
        if (
            # Random-looking subdomains (enumeration artifacts)
            any(c.isdigit() for c in name[:8]) and len(name.split(".")[0]) > 8
            # IP addresses encoded as subdomains (DNS rebinding probes)
            or "_" in name and any(c.isdigit() for c in name)
            # Known bad patterns
            or "baidu" in name_lower or "test" in name_lower
        ):
            recon_indicators.append({"name": name, "count": cnt, "reason": "enum_or_rebind_probe"})

    top_subdomains = sorted(by_name.items(), key=lambda x: x[1], reverse=True)

    return json.dumps({
        "period_hours": min(hours, 23),
        "total_queries": sum(by_name.values()),
        "unique_subdomains_queried": len(by_name),
        "query_type_breakdown": {k: v for k, v in sorted(by_type.items(), key=lambda x: x[1], reverse=True)},
        "top_subdomains": [{"name": n, "count": c} for n, c in top_subdomains[:30]],
        "nxdomain_queries": sorted(nxdomain, key=lambda x: x["count"], reverse=True)[:10],
        "recon_indicators": sorted(recon_indicators, key=lambda x: x["count"], reverse=True)[:10],
    }, indent=2)
