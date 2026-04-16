"""
First Light REST API v1

Thin REST layer over LangChain tools — same data the agents and MCP server use.
Designed for Dashy dashboard widgets and general HTTP consumers.

All endpoints are GET, cached via cachetools TTLCache, and return a consistent
JSON envelope: {"status": "ok"|"error", "data": ..., "cached": bool, "timestamp": str}
"""

import json
import logging
import re
import time
from datetime import datetime, timezone

import httpx
from cachetools import TTLCache
from fastapi import APIRouter, Depends, Query

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Caching ─────────────────────────────────────────────────────────────────────

_cache_60 = TTLCache(maxsize=16, ttl=60)
_cache_120 = TTLCache(maxsize=16, ttl=120)
_cache_300 = TTLCache(maxsize=32, ttl=300)
_cache_600 = TTLCache(maxsize=4, ttl=600)

_CACHE_TIERS = {60: _cache_60, 120: _cache_120, 300: _cache_300, 600: _cache_600}


def _cached(ttl: int, key: str, fn):
    """Check cache; on miss call fn(), store result, return (data, cached_bool)."""
    cache = _CACHE_TIERS[ttl]
    hit = cache.get(key)
    if hit is not None:
        return hit, True
    result = fn()
    cache[key] = result
    return result, False


# ── Response helpers ────────────────────────────────────────────────────────────

def _envelope(data, cached: bool = False):
    return {
        "status": "ok",
        "data": data,
        "cached": cached,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _error_envelope(detail: str, status_code: int = 502):
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "error",
            "error": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


def _invoke_tool(tool_fn, args: dict | None = None):
    """Call a LangChain tool and parse the result. Returns parsed data or raises."""
    raw = tool_fn.invoke(args or {})
    # Tools return strings — try to parse as JSON
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and "error" in parsed:
            raise ValueError(parsed["error"])
        return parsed
    except (json.JSONDecodeError, TypeError):
        # Not JSON — could be tab-separated or error string
        if isinstance(raw, str) and raw.startswith("Error"):
            raise ValueError(raw)
        return raw


# ── TSV parser ──────────────────────────────────────────────────────────────────

_SECTION_RE = re.compile(r"^===\s*(.+?)\s*===$")


def _parse_tsv(text: str) -> list[dict] | dict:
    """Parse ClickHouse tab-separated output into structured JSON.

    Handles two formats:
    1. Single table: header row + data rows (returns list of dicts)
    2. Multi-section with === label === separators (returns dict of section -> list)
    """
    if not text or text in ("No results found",):
        return []

    lines = text.strip().split("\n")

    # Check if multi-section
    sections = {}
    current_label = None
    current_lines = []

    for line in lines:
        m = _SECTION_RE.match(line)
        if m:
            if current_label is not None:
                sections[current_label] = _parse_single_tsv("\n".join(current_lines))
            current_label = m.group(1)
            current_lines = []
        else:
            current_lines.append(line)

    if current_label is not None:
        sections[current_label] = _parse_single_tsv("\n".join(current_lines))
        return sections

    # Single table
    return _parse_single_tsv(text)


def _parse_single_tsv(text: str) -> list[dict]:
    """Parse a single tab-separated table into a list of dicts."""
    lines = [l for l in text.strip().split("\n") if l.strip()]
    if len(lines) < 2:
        return []
    headers = lines[0].split("\t")
    rows = []
    for line in lines[1:]:
        values = line.split("\t")
        row = {}
        for i, h in enumerate(headers):
            val = values[i] if i < len(values) else ""
            # Try numeric conversion
            try:
                row[h] = int(val)
            except ValueError:
                try:
                    row[h] = float(val)
                except ValueError:
                    row[h] = val
        rows.append(row)
    return rows


# ── Auth dependency (imported from app at mount time) ───────────────────────────
# We re-import _check_auth so the router can use the same auth as the main app.

def _get_auth_dep():
    from ui.app import _check_auth
    return Depends(_check_auth)


# We apply auth at the router level via dependencies parameter.
# This is set up when the router is included in app.py.


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/health/infra")
async def health_infra():
    """Infrastructure health: collectors, log ingestion, containers, ntopng."""
    from agent.tools.infra_health import query_reporting_infra_health

    try:
        data, cached = _cached(120, "health_infra", lambda: _invoke_tool(query_reporting_infra_health))
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/health/proxmox")
async def health_proxmox():
    """Proxmox VE health: nodes, VMs, containers, storage."""
    from agent.tools.proxmox_tools import query_proxmox_health

    try:
        data, cached = _cached(120, "health_proxmox", lambda: _invoke_tool(query_proxmox_health))
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/health/uptime")
async def health_uptime():
    """Uptime Kuma monitor status."""
    from agent.tools.uptime_kuma import query_uptime_kuma_status

    try:
        data, cached = _cached(60, "health_uptime", lambda: _invoke_tool(query_uptime_kuma_status))
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/health/uptime/incidents")
async def health_uptime_incidents(hours: int = Query(default=24, ge=1, le=168)):
    """Recent downtime incidents."""
    from agent.tools.uptime_kuma import query_uptime_kuma_incidents

    try:
        key = f"uptime_incidents_{hours}"
        data, cached = _cached(60, key, lambda: _invoke_tool(query_uptime_kuma_incidents, {"hours": hours}))
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# DNS / ADGUARD ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/dns/summary")
async def dns_summary(hours: int = Query(default=24, ge=1, le=168)):
    """Aggregate DNS stats: totals, block rate, anomaly counts."""
    from agent.tools.metrics import query_adguard_network_summary

    try:
        key = f"dns_summary_{hours}"
        data, cached = _cached(300, key, lambda: _parse_tsv(query_adguard_network_summary.invoke({"hours": hours})))
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/dns/top-clients")
async def dns_top_clients(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
):
    """Top DNS clients by query volume."""
    from agent.tools.metrics import query_adguard_top_clients

    try:
        key = f"dns_top_clients_{hours}_{limit}"
        data, cached = _cached(300, key, lambda: _parse_tsv(query_adguard_top_clients.invoke({"hours": hours, "limit": limit})))
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/dns/block-rates")
async def dns_block_rates(
    hours: int = Query(default=24, ge=1, le=168),
    min_block_rate: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=20, ge=1, le=100),
):
    """DNS block rates per client."""
    from agent.tools.metrics import query_adguard_block_rates

    try:
        key = f"dns_block_rates_{hours}_{min_block_rate}_{limit}"
        data, cached = _cached(
            300, key,
            lambda: _parse_tsv(query_adguard_block_rates.invoke({
                "hours": hours, "min_block_rate": min_block_rate, "limit": limit,
            })),
        )
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/dns/blocked-domains")
async def dns_blocked_domains(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
):
    """Top blocked domains."""
    from agent.tools.metrics import query_adguard_blocked_domains

    try:
        key = f"dns_blocked_domains_{hours}_{limit}"
        data, cached = _cached(
            300, key,
            lambda: _parse_tsv(query_adguard_blocked_domains.invoke({"hours": hours, "limit": limit})),
        )
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/dns/threat-signals")
async def dns_threat_signals(hours: int = Query(default=24, ge=1, le=168)):
    """DNS threat signals: beaconing, tunneling, anomalies."""
    from agent.tools.metrics import query_adguard_threat_signals

    try:
        key = f"dns_threat_signals_{hours}"
        data, cached = _cached(300, key, lambda: _parse_tsv(query_adguard_threat_signals.invoke({"hours": hours})))
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/security/summary")
async def security_summary(hours: int = Query(default=1, ge=1, le=24)):
    """Security summary: threats, blocks, attacks."""
    from agent.tools.logs import query_security_summary

    try:
        key = f"security_summary_{hours}"
        data, cached = _cached(120, key, lambda: _invoke_tool(query_security_summary, {"hours": hours}))
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/security/threats")
async def security_threats(
    hours: int = Query(default=24, ge=1, le=168),
    min_score: int = Query(default=0, ge=0, le=100),
):
    """Threat intel summary: enriched blocked IPs with reputation data."""
    from agent.tools.threat_intel_tools import query_threat_intel_summary

    try:
        key = f"security_threats_{hours}_{min_score}"
        data, cached = _cached(
            300, key,
            lambda: _invoke_tool(query_threat_intel_summary, {"hours": hours, "min_score": min_score}),
        )
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/security/threat-coverage")
async def security_threat_coverage():
    """Threat intel enrichment coverage stats."""
    from agent.tools.threat_intel_tools import query_threat_intel_coverage

    try:
        data, cached = _cached(300, "threat_coverage", lambda: _invoke_tool(query_threat_intel_coverage))
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# STATUS & WEATHER
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/status")
async def system_status():
    """Enhanced system status."""
    from ui.app import _system_status

    try:
        data, cached = _cached(60, "system_status", _system_status)
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


@router.get("/weather")
async def weather():
    """Current weather via wttr.in (no API key required)."""
    try:
        data, cached = _cached(600, "weather", _fetch_weather)
        return _envelope(data, cached)
    except Exception as e:
        return _error_envelope(str(e))


def _fetch_weather() -> dict:
    """Fetch weather from wttr.in in JSON format."""
    # Dallas, TX — adjust if needed
    with httpx.Client(timeout=10.0) as client:
        resp = client.get("https://wttr.in/Dallas,TX?format=j1")
    if resp.status_code != 200:
        raise ValueError(f"wttr.in returned HTTP {resp.status_code}")
    full = resp.json()
    current = full.get("current_condition", [{}])[0]
    return {
        "location": "Dallas, TX",
        "temp_f": current.get("temp_F"),
        "temp_c": current.get("temp_C"),
        "feels_like_f": current.get("FeelsLikeF"),
        "humidity": current.get("humidity"),
        "description": current.get("weatherDesc", [{}])[0].get("value"),
        "wind_mph": current.get("windspeedMiles"),
        "wind_dir": current.get("winddir16Point"),
        "precip_mm": current.get("precipMM"),
        "uv_index": current.get("uvIndex"),
        "visibility_miles": current.get("visibilityMiles"),
    }
