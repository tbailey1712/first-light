"""
CrowdSec LAPI tools — queries local CrowdSec instance for alerts and active decisions.

CrowdSec detects intrusion attempts from syslog (pfSense, SSH, etc.) and builds
a list of active bans (decisions). The LAPI is at http://fl-crowdsec:8080.

Requires CROWDSEC_API_KEY in .env (a bouncer key created with:
  docker exec fl-crowdsec cscli bouncers add firstlight-agent)
"""

import json
import logging
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)

_LAPI_URL = "http://fl-crowdsec:8080"


def _crowdsec_get(path: str, params: Optional[dict] = None) -> dict | list:
    cfg = get_config()
    api_key = cfg.crowdsec_api_key
    if not api_key:
        return {"error": "CROWDSEC_API_KEY not configured in .env"}
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                f"{_LAPI_URL}{path}",
                headers={"X-Api-Key": api_key},
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
    data = _crowdsec_get("/v1/alerts", {"limit": limit})
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
    data = _crowdsec_get("/v1/decisions", {"limit": limit})
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
