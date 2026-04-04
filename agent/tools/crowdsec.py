"""
CrowdSec LAPI tools — queries local CrowdSec instance for alerts and active decisions.

CrowdSec detects intrusion attempts from syslog (pfSense, SSH, etc.) and builds
a list of active bans (decisions). The LAPI is at http://fl-crowdsec:8080.

Two auth tiers in CrowdSec LAPI:
  - Bouncer key (X-Api-Key):  /v1/decisions  — enforcement consumers
    Created with: docker exec fl-crowdsec cscli bouncers add firstlight-agent
  - Machine JWT (Bearer):     /v1/alerts     — watchers that read detection events
    Created with: docker exec fl-crowdsec cscli machines add firstlight-watcher --password ...

.env vars required:
  CROWDSEC_API_KEY          bouncer key  → used by query_crowdsec_decisions
  CROWDSEC_MACHINE_ID       watcher login → used by query_crowdsec_alerts
  CROWDSEC_MACHINE_PASSWORD watcher password
"""

import json
import logging
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)

_LAPI_URL = "http://fl-crowdsec:8080"


def _bouncer_get(path: str, params: Optional[dict] = None) -> dict | list:
    """GET using bouncer key (X-Api-Key). Works for /v1/decisions only."""
    cfg = get_config()
    if not cfg.crowdsec_api_key:
        return {"error": "CROWDSEC_API_KEY not configured in .env"}
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                f"{_LAPI_URL}{path}",
                headers={"X-Api-Key": cfg.crowdsec_api_key},
                params=params or {},
            )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}", "body": resp.text[:300]}
    except Exception as e:
        return {"error": str(e)}


def _watcher_get(path: str, params: Optional[dict] = None) -> dict | list:
    """GET using machine JWT. Required for /v1/alerts (watcher-only endpoint)."""
    cfg = get_config()
    if not cfg.crowdsec_machine_id or not cfg.crowdsec_machine_password:
        return {"error": "CROWDSEC_MACHINE_ID / CROWDSEC_MACHINE_PASSWORD not configured in .env"}
    try:
        with httpx.Client(timeout=10.0) as client:
            login = client.post(
                f"{_LAPI_URL}/v1/watchers/login",
                json={
                    "machine_id": cfg.crowdsec_machine_id,
                    "password": cfg.crowdsec_machine_password,
                    "scenarios": [],
                },
            )
            if login.status_code != 200:
                return {"error": f"CrowdSec watcher login failed: HTTP {login.status_code}", "body": login.text[:200]}
            token = login.json().get("token")
            resp = client.get(
                f"{_LAPI_URL}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=params or {},
            )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}", "body": resp.text[:300]}
    except Exception as e:
        return {"error": str(e)}


@tool
def query_crowdsec_alerts(limit: int = 50) -> str:
    """Get recent CrowdSec alerts — IPs that triggered detection scenarios.

    Alerts are fired when an IP matches a scenario (e.g. ssh-bruteforce,
    pfsense-scan, http-probing). Each alert shows the IP, scenario matched,
    originating country, and when it was detected.

    Args:
        limit: Max alerts to return (default: 50)

    Returns:
        JSON with recent alerts including IP, scenario, country, and timestamp.
    """
    data = _watcher_get("/v1/alerts", {"limit": limit})
    if isinstance(data, dict) and "error" in data:
        return json.dumps(data)

    if not data:
        return json.dumps({"status": "clean", "message": "No alerts in CrowdSec"})

    alerts = []
    for alert in data:
        source = alert.get("source", {})
        alerts.append({
            "ip": source.get("ip", "unknown"),
            "country": source.get("cn", "unknown"),
            "as_name": source.get("as_name", ""),
            "scenario": alert.get("scenario", "unknown"),
            "decisions": len(alert.get("decisions", [])),
            "events_count": alert.get("events_count", 0),
            "started_at": alert.get("start_at", ""),
            "stopped_at": alert.get("stop_at", ""),
        })

    return json.dumps({"total": len(alerts), "alerts": alerts}, indent=2)


@tool
def query_crowdsec_decisions(limit: int = 100) -> str:
    """Get active CrowdSec decisions — IPs currently banned or rate-limited.

    Decisions are the enforcement output of CrowdSec — IPs that have been
    banned based on triggered scenarios. Includes the ban reason, duration,
    and originating scenario.

    Args:
        limit: Max decisions to return (default: 100)

    Returns:
        JSON with active decisions including banned IP, type, scenario, and expiry.
    """
    data = _bouncer_get("/v1/decisions", {"limit": limit})
    if isinstance(data, dict) and "error" in data:
        return json.dumps(data)

    if not data:
        return json.dumps({"status": "no_active_decisions", "message": "No IPs currently banned by CrowdSec"})

    decisions = []
    for d in data:
        decisions.append({
            "ip": d.get("value", "unknown"),
            "type": d.get("type", "ban"),
            "scenario": d.get("scenario", "unknown"),
            "duration": d.get("duration", ""),
            "origin": d.get("origin", ""),
            "created_at": d.get("created_at", ""),
        })

    return json.dumps({"total": len(decisions), "decisions": decisions}, indent=2)


@tool
def query_crowdsec_metrics() -> str:
    """Get CrowdSec acquisition and decision metrics to verify log ingestion health.

    Combines two sources:
    - LAPI connectivity check via /v1/alerts (watcher JWT auth)
    - Prometheus metrics endpoint at http://fl-crowdsec:6060/metrics (no auth)

    Extracted metrics:
    - cs_active_decisions: current number of active bans
    - cs_alerts: total alerts ever fired
    - cs_lapi_requests_total: LAPI endpoint call counts
    - cs_parser_hits_total / cs_parser_ok_total: parse rates per log source

    Returns:
        JSON with active_decisions, total_alerts, lapi_requests, and sources list
        of {source, lines_read, lines_parsed, parse_rate_pct}.
    """
    # Step 1: confirm LAPI connectivity via watcher auth (limit=1 to minimise load)
    lapi_ok = True
    lapi_error: Optional[str] = None
    connectivity_check = _watcher_get("/v1/alerts", {"limit": 1})
    if isinstance(connectivity_check, dict) and "error" in connectivity_check:
        lapi_ok = False
        lapi_error = connectivity_check["error"]

    # Step 2: scrape the Prometheus metrics endpoint (unauthenticated)
    _METRICS_URL = "http://fl-crowdsec:6060/metrics"
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(_METRICS_URL)
            resp.raise_for_status()
            prom_text = resp.text
    except Exception as e:
        return json.dumps({
            "lapi_reachable": lapi_ok,
            "lapi_error": lapi_error,
            "error": f"Prometheus metrics endpoint unreachable: {e}",
        })

    # Step 3: parse Prometheus text format
    active_decisions: Optional[int] = None
    total_alerts: Optional[int] = None
    lapi_requests: dict = {}          # route -> count
    parser_hits: dict = {}            # source -> int
    parser_ok: dict = {}              # source -> int

    for line in prom_text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue

        # cs_active_decisions <value>
        if line.startswith("cs_active_decisions "):
            try:
                active_decisions = int(float(line.split()[-1]))
            except ValueError:
                pass

        # cs_alerts <value>
        elif line.startswith("cs_alerts "):
            try:
                total_alerts = int(float(line.split()[-1]))
            except ValueError:
                pass

        # cs_lapi_requests_total{route="/v1/...",...} <value>
        elif line.startswith("cs_lapi_requests_total{"):
            try:
                labels_part = line[len("cs_lapi_requests_total{"):line.index("}")]
                value_part = line[line.index("}") + 1:].strip()
                labels = dict(
                    kv.split("=", 1) for kv in labels_part.split(",") if "=" in kv
                )
                route = labels.get("route", "").strip('"')
                count = int(float(value_part))
                lapi_requests[route] = lapi_requests.get(route, 0) + count
            except Exception:
                pass

        # cs_parser_hits_total{source="...",...} <value>
        elif line.startswith("cs_parser_hits_total{"):
            try:
                labels_part = line[len("cs_parser_hits_total{"):line.index("}")]
                value_part = line[line.index("}") + 1:].strip()
                labels = dict(
                    kv.split("=", 1) for kv in labels_part.split(",") if "=" in kv
                )
                source = labels.get("source", "unknown").strip('"')
                count = int(float(value_part))
                parser_hits[source] = parser_hits.get(source, 0) + count
            except Exception:
                pass

        # cs_parser_ok_total{source="...",...} <value>
        elif line.startswith("cs_parser_ok_total{"):
            try:
                labels_part = line[len("cs_parser_ok_total{"):line.index("}")]
                value_part = line[line.index("}") + 1:].strip()
                labels = dict(
                    kv.split("=", 1) for kv in labels_part.split(",") if "=" in kv
                )
                source = labels.get("source", "unknown").strip('"')
                count = int(float(value_part))
                parser_ok[source] = parser_ok.get(source, 0) + count
            except Exception:
                pass

    # Build per-source parse rate summary
    all_sources = sorted(set(list(parser_hits.keys()) + list(parser_ok.keys())))
    sources = []
    for src in all_sources:
        hits = parser_hits.get(src, 0)
        ok = parser_ok.get(src, 0)
        rate = round(ok / hits * 100, 1) if hits > 0 else 0.0
        sources.append({
            "source": src,
            "lines_read": hits,
            "lines_parsed": ok,
            "parse_rate_pct": rate,
        })

    return json.dumps({
        "lapi_reachable": lapi_ok,
        "lapi_error": lapi_error,
        "active_decisions": active_decisions,
        "total_alerts": total_alerts,
        "lapi_requests": {
            k: v for k, v in sorted(lapi_requests.items(), key=lambda x: x[1], reverse=True)
        },
        "sources": sources,
    }, indent=2)
