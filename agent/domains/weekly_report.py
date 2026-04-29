"""
Weekly Report Data Collectors

Lightweight functions that call tools directly (no ReAct loops) to gather
7-day trend data for the weekly report. Each returns a dict with structured
data. Errors are caught and returned as {"error": str} — never crash the
whole report.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _invoke(tool, params: dict | None = None) -> Any:
    """Invoke a LangChain tool and parse JSON result. Returns parsed dict/list or raw string."""
    raw = tool.invoke(params or {})
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


def collect_dns_trends(hours: int = 168) -> dict:
    """Collect 7-day DNS query volume, block rates, and top clients."""
    try:
        from agent.tools.metrics import (
            query_adguard_network_summary,
            query_adguard_block_rates,
            query_adguard_top_clients,
        )
        return {
            "network_summary": _invoke(query_adguard_network_summary, {"hours": hours}),
            "block_rates": _invoke(query_adguard_block_rates, {"hours": hours}),
            "top_clients": _invoke(query_adguard_top_clients, {"hours": hours, "limit": 20}),
        }
    except Exception as e:
        logger.error("collect_dns_trends failed: %s", e, exc_info=True)
        return {"error": str(e)}


def collect_firewall_trends(hours: int = 168) -> dict:
    """Collect 7-day firewall block volume and auth event summary."""
    try:
        from agent.tools.logs import query_security_summary, query_auth_events
        return {
            "security_summary": _invoke(query_security_summary, {"hours": hours}),
            "auth_events": _invoke(query_auth_events, {"hours": hours}),
        }
    except Exception as e:
        logger.error("collect_firewall_trends failed: %s", e, exc_info=True)
        return {"error": str(e)}


def collect_wireless_health(hours: int = 168) -> dict:
    """Collect 7-day wireless health events and current client snapshot."""
    try:
        from agent.tools.logs import query_wireless_health
        from agent.tools.unifi_tools import query_unifi_clients
        return {
            "wireless_events": _invoke(query_wireless_health, {"hours": hours}),
            "unifi_clients": _invoke(query_unifi_clients),
        }
    except Exception as e:
        logger.error("collect_wireless_health failed: %s", e, exc_info=True)
        return {"error": str(e)}


def collect_network_performance(days: int = 7) -> dict:
    """Collect WAN bandwidth daily averages and interface utilization."""
    try:
        from agent.tools.switch_tools import (
            query_wan_bandwidth_daily,
            query_pfsense_interface_traffic,
        )
        return {
            "wan_bandwidth": _invoke(query_wan_bandwidth_daily, {"days": days}),
            "interface_traffic": _invoke(query_pfsense_interface_traffic, {"hours": days * 24}),
        }
    except Exception as e:
        logger.error("collect_network_performance failed: %s", e, exc_info=True)
        return {"error": str(e)}


def collect_infrastructure_capacity() -> dict:
    """Collect Proxmox weekly trends and QNAP health snapshot."""
    try:
        from agent.tools.proxmox_tools import query_proxmox_trends, query_proxmox_health
        from agent.tools.qnap_tools import query_qnap_health
        return {
            "proxmox_trends": _invoke(query_proxmox_trends, {"timeframe": "week"}),
            "proxmox_health": _invoke(query_proxmox_health),
            "qnap_health": _invoke(query_qnap_health),
        }
    except Exception as e:
        logger.error("collect_infrastructure_capacity failed: %s", e, exc_info=True)
        return {"error": str(e)}


def collect_validator_summary() -> dict:
    """Collect current validator health snapshot."""
    try:
        from agent.tools.validator import query_validator_health
        return {
            "validator_health": _invoke(query_validator_health),
        }
    except Exception as e:
        logger.error("collect_validator_summary failed: %s", e, exc_info=True)
        return {"error": str(e)}


def collect_security_posture(hours: int = 168) -> dict:
    """Collect 7-day threat intel summary, CrowdSec activity, and new devices."""
    try:
        from agent.tools.threat_intel_tools import query_threat_intel_summary
        from agent.tools.crowdsec import query_crowdsec_alerts, query_crowdsec_decisions
        from agent.tools.metrics import query_adguard_new_devices
        return {
            "threat_intel": _invoke(query_threat_intel_summary, {"hours": hours}),
            "crowdsec_alerts": _invoke(query_crowdsec_alerts, {"limit": 200}),
            "crowdsec_decisions": _invoke(query_crowdsec_decisions, {"limit": 200}),
            "new_devices": _invoke(query_adguard_new_devices, {"hours": hours}),
        }
    except Exception as e:
        logger.error("collect_security_posture failed: %s", e, exc_info=True)
        return {"error": str(e)}


# Collector registry — maps name to function for parallel execution
WEEKLY_COLLECTORS = {
    "dns_trends": collect_dns_trends,
    "firewall_trends": collect_firewall_trends,
    "wireless_health": collect_wireless_health,
    "network_performance": collect_network_performance,
    "infrastructure_capacity": collect_infrastructure_capacity,
    "validator_summary": collect_validator_summary,
    "security_posture": collect_security_posture,
}
