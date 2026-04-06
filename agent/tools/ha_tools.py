"""
Home Assistant tools — queries the HA REST API for entity states,
logbook events, and security-relevant home automation activity.

Requires HA_TOKEN (long-lived access token) in .env.
Create one at: Home Assistant → Profile → Security → Long-Lived Access Tokens.
"""

import json
import logging
from typing import Optional

import httpx
from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)

# Domains that matter for security / home state analysis
_SECURITY_DOMAINS = {
    "lock", "alarm_control_panel", "binary_sensor", "person",
    "device_tracker", "cover", "input_boolean",
}
_INTERESTING_DOMAINS = _SECURITY_DOMAINS | {
    "climate", "sensor", "switch", "light", "automation", "script",
}


def _ha_base_url() -> Optional[str]:
    cfg = get_config()
    if not cfg.ha_token:
        return None
    scheme = "https" if cfg.ha_ssl else "http"
    return f"{scheme}://{cfg.ha_host}:{cfg.ha_port}"


def _ha_headers() -> dict:
    cfg = get_config()
    return {
        "Authorization": f"Bearer {cfg.ha_token}",
        "Content-Type": "application/json",
    }


def _ha_client(base_url: str) -> httpx.Client:
    """Return an httpx.Client configured for the HA API (SSL verification disabled for self-signed certs)."""
    cfg = get_config()
    return httpx.Client(
        base_url=base_url,
        headers=_ha_headers(),
        timeout=15.0,
        verify=not cfg.ha_ssl,  # self-signed cert — skip verification
    )


def _not_configured() -> str:
    return json.dumps({
        "error": "Home Assistant not configured — add HA_TOKEN to .env. "
                 "Create at: HA → Profile → Security → Long-Lived Access Tokens."
    })


@tool
def query_ha_logbook(hours: int = 24, domains: str = "") -> str:
    """Get Home Assistant logbook events — entity state changes, automations triggered, alerts.

    The logbook shows human-readable descriptions of what happened in the home:
    locks locked/unlocked, motion detected, doors opened, automations fired, etc.
    Filters to security-relevant domains by default.

    Args:
        hours: Lookback period in hours (default: 24).
        domains: Comma-separated domain filter, e.g. "lock,binary_sensor,person".
                 Defaults to all security-relevant domains if empty.

    Returns:
        JSON with logbook entries grouped by domain, plus a security_events list
        flagging any lock, alarm, or access events outside normal hours (22:00–07:00).
    """
    base_url = _ha_base_url()
    if base_url is None:
        return _not_configured()

    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = (now - timedelta(hours=hours)).isoformat()

    filter_domains = [d.strip() for d in domains.split(",") if d.strip()] if domains else list(_SECURITY_DOMAINS)

    try:
        with _ha_client(base_url) as client:
            resp = client.get(
                f"/api/logbook/{start}",
                params={"end_time": now.isoformat()},
            )
            if resp.status_code == 401:
                return json.dumps({"error": "HA token invalid or expired — regenerate in HA Profile."})
            if resp.status_code != 200:
                return json.dumps({"error": f"HA API error {resp.status_code}: {resp.text[:200]}"})
            entries = resp.json()
    except Exception as e:
        return json.dumps({"error": str(e)})

    # Filter and group by domain
    by_domain: dict = {}
    security_events = []

    for entry in entries:
        domain = entry.get("domain", "")
        entity_id = entry.get("entity_id", "")
        name = entry.get("name", entity_id)
        message = entry.get("message", "")
        when = entry.get("when", "")

        if filter_domains and domain not in filter_domains:
            continue

        item = {"entity": entity_id, "name": name, "message": message, "when": when}
        by_domain.setdefault(domain, []).append(item)

        # Flag security-relevant events at unusual hours
        try:
            dt = datetime.fromisoformat(when.replace("Z", "+00:00"))
            hour = dt.hour
            is_odd_hour = hour >= 22 or hour < 7
        except Exception:
            is_odd_hour = False

        is_security = domain in {"lock", "alarm_control_panel", "binary_sensor"}
        is_notable = any(kw in message.lower() for kw in ("unlock", "open", "trigger", "armed", "disarm", "detected"))

        if (is_security and is_notable) or (is_odd_hour and is_notable):
            security_events.append({
                "entity": entity_id,
                "name": name,
                "message": message,
                "when": when,
                "flag": "odd_hours" if is_odd_hour else "security_event",
            })

    return json.dumps({
        "hours": hours,
        "total_events": sum(len(v) for v in by_domain.values()),
        "by_domain": by_domain,
        "security_events": security_events,
    }, indent=2)


@tool
def query_ha_entity_states(domains: str = "") -> str:
    """Get current state of Home Assistant entities, filtered to security-relevant domains.

    Returns live entity states: lock status, alarm state, presence (who's home),
    door/window sensors, climate, and device trackers.

    Args:
        domains: Comma-separated domain filter, e.g. "lock,person,binary_sensor".
                 Defaults to all security-relevant domains if empty.

    Returns:
        JSON with entity states grouped by domain, highlighting anything
        in an unexpected state (lock unlocked, alarm disarmed, etc.).
    """
    base_url = _ha_base_url()
    if base_url is None:
        return _not_configured()

    try:
        with _ha_client(base_url) as client:
            resp = client.get("/api/states")
            if resp.status_code == 401:
                return json.dumps({"error": "HA token invalid or expired."})
            if resp.status_code != 200:
                return json.dumps({"error": f"HA API error {resp.status_code}"})
            all_states = resp.json()
    except Exception as e:
        return json.dumps({"error": str(e)})

    filter_domains = [d.strip() for d in domains.split(",") if d.strip()] if domains else list(_SECURITY_DOMAINS)

    by_domain: dict = {}
    attention: list = []

    for entity in all_states:
        entity_id = entity.get("entity_id", "")
        domain = entity_id.split(".")[0] if "." in entity_id else ""
        if filter_domains and domain not in filter_domains:
            continue

        state = entity.get("state", "unknown")
        attrs = entity.get("attributes", {})
        friendly = attrs.get("friendly_name", entity_id)
        last_changed = entity.get("last_changed", "")

        entry = {
            "entity_id": entity_id,
            "name": friendly,
            "state": state,
            "last_changed": last_changed,
        }
        by_domain.setdefault(domain, []).append(entry)

        # Flag unexpected states
        if domain == "lock" and state == "unlocked":
            attention.append(f"Lock {friendly} is UNLOCKED (last changed: {last_changed})")
        elif domain == "alarm_control_panel" and state == "disarmed":
            attention.append(f"Alarm {friendly} is disarmed")
        elif domain == "binary_sensor" and state == "on" and any(
            kw in entity_id for kw in ("door", "window", "motion", "presence")
        ):
            attention.append(f"Sensor {friendly} is active/open")

    return json.dumps({
        "entity_count": sum(len(v) for v in by_domain.values()),
        "by_domain": by_domain,
        "attention": attention,
    }, indent=2)


@tool
def query_ha_entity_history(entity_id: str, hours: int = 24) -> str:
    """Get the state history of a specific Home Assistant entity.

    Useful for investigating a specific device: how many times did the front door
    lock/unlock today? When was motion last detected? What was the alarm state history?

    Args:
        entity_id: Full HA entity ID, e.g. "lock.front_door_lock" or "person.tony".
        hours: Lookback period in hours (default: 24).

    Returns:
        JSON with timestamped state transitions for the entity.
    """
    base_url = _ha_base_url()
    if base_url is None:
        return _not_configured()

    from datetime import datetime, timedelta, timezone
    start = (datetime.now(timezone.utc) - timedelta(hours=hours)).replace(microsecond=0).isoformat()

    try:
        with _ha_client(base_url) as client:
            resp = client.get(
                f"/api/history/period/{start}",
                params={"filter_entity_id": entity_id, "minimal_response": "true"},
            )
            if resp.status_code == 401:
                return json.dumps({"error": "HA token invalid or expired."})
            if resp.status_code != 200:
                return json.dumps({"error": f"HA API error {resp.status_code}"})
            history = resp.json()
    except Exception as e:
        return json.dumps({"error": str(e)})

    if not isinstance(history, list):
        return json.dumps({"error": f"Unexpected response format from HA history API: {type(history).__name__}"})

    # history is a list of lists (one per entity)
    transitions = []
    for entity_history in history:
        if not isinstance(entity_history, list):
            continue
        for state_record in entity_history:
            transitions.append({
                "state": state_record.get("state"),
                "last_changed": state_record.get("last_changed"),
            })

    return json.dumps({
        "entity_id": entity_id,
        "hours": hours,
        "transitions": transitions,
        "total_changes": len(transitions),
    }, indent=2)


@tool
def query_ha_metrics(domains: str = "") -> str:
    """Get current numeric and state metrics from Home Assistant entities.

    Fetches entity states from the HA REST API, filtered to metric-relevant domains:
    sensor (temperature, humidity, power, energy), climate (setpoints, HVAC mode),
    binary_sensor (occupancy, door/window, motion), device_tracker (presence).

    Useful for: power consumption, climate conditions, occupancy patterns,
    and building a picture of home state at a point in time.

    Args:
        domains: Comma-separated domain filter, e.g. "sensor,climate".
                 Defaults to sensor, climate, binary_sensor, device_tracker.

    Returns:
        JSON with entities grouped by domain. Numeric sensor states are
        parsed to float. Includes an 'anomalies' list for sensors reporting
        unavailable/unknown state or suspiciously out-of-range values.
    """
    base_url = _ha_base_url()
    if base_url is None:
        return _not_configured()

    _METRIC_DOMAINS = {"sensor", "climate", "binary_sensor", "device_tracker"}
    filter_domains = {d.strip() for d in domains.split(",") if d.strip()} if domains else _METRIC_DOMAINS

    try:
        with _ha_client(base_url) as client:
            resp = client.get("/api/states")
            if resp.status_code == 401:
                return json.dumps({"error": "HA token invalid or expired."})
            if resp.status_code != 200:
                return json.dumps({"error": f"HA API error {resp.status_code}"})
            all_states = resp.json()
    except Exception as e:
        return json.dumps({"error": str(e)})

    by_domain: dict = {}
    anomalies: list = []

    for entity in all_states:
        entity_id = entity.get("entity_id", "")
        domain = entity_id.split(".")[0] if "." in entity_id else ""
        if domain not in filter_domains:
            continue

        state = entity.get("state", "unknown")
        attrs = entity.get("attributes", {})
        friendly = attrs.get("friendly_name", entity_id)
        unit = attrs.get("unit_of_measurement", "")
        last_changed = entity.get("last_changed", "")

        # Try to parse numeric value
        numeric_value = None
        try:
            numeric_value = float(state)
        except (ValueError, TypeError):
            pass

        entry = {
            "entity_id": entity_id,
            "name": friendly,
            "state": state,
            "unit": unit,
            "last_changed": last_changed,
        }
        if numeric_value is not None:
            entry["value"] = numeric_value

        # Climate extras
        if domain == "climate":
            entry["hvac_mode"] = attrs.get("hvac_action", attrs.get("hvac_mode", ""))
            entry["current_temp"] = attrs.get("current_temperature")
            entry["target_temp"] = attrs.get("temperature")

        by_domain.setdefault(domain, []).append(entry)

        # Flag unavailable/unknown sensors
        if state in ("unavailable", "unknown"):
            anomalies.append({"entity_id": entity_id, "name": friendly, "issue": state})

    # Summarise sensor counts and notable values
    sensor_summary = {}
    for e in by_domain.get("sensor", []):
        if e.get("unit") in ("W", "kWh", "°F", "°C", "%"):
            sensor_summary.setdefault(e["unit"], []).append({
                "name": e["name"], "value": e.get("value"), "entity_id": e["entity_id"]
            })

    return json.dumps({
        "domains_queried": sorted(filter_domains),
        "entity_count": sum(len(v) for v in by_domain.values()),
        "by_domain": by_domain,
        "sensor_summary": sensor_summary,
        "anomalies": anomalies,
    }, indent=2)
