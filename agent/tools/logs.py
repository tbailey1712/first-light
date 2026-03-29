"""
Tools for querying and analyzing logs from SigNoz/ClickHouse.

Returns summaries for LLM analysis + sample log details for investigation.
"""

import httpx
import json
import re
from typing import Literal, Optional, Dict, List
from datetime import datetime, timezone

from langchain_core.tools import tool

from agent.config import get_config


@tool
def query_security_summary(hours: int = 1) -> str:
    """Get security summary showing threats, blocks, and attacks.

    Args:
        hours: Lookback period in hours (default: 1, max: 24)

    Returns:
        JSON with summary stats + top threats with sample logs
    """
    # Limit hours to prevent excessive data
    hours = min(hours, 24)

    # Query pfSense firewall blocks
    pfsense_query = f"""
    SELECT
        attributes_string['pfsense.src_ip'] as src_ip,
        attributes_string['pfsense.dst_port'] as dst_port,
        attributes_string['pfsense.protocol'] as protocol,
        COUNT(*) as block_count,
        MIN(timestamp) as first_seen,
        MAX(timestamp) as last_seen,
        groupArray(body) as sample_logs
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND resources_string['service.name'] = 'filterlog'
      AND attributes_string['pfsense.action'] = 'block'
      AND attributes_string['pfsense.src_ip'] NOT LIKE '192.168.%'  -- External only
    GROUP BY src_ip, dst_port, protocol
    ORDER BY block_count DESC
    LIMIT 10
    FORMAT JSONEachRow
    """

    # Query ntopng security alerts
    ntopng_query = f"""
    SELECT
        attributes_string['ntopng.alert_type'] as alert_type,
        attributes_string['ntopng.severity'] as severity,
        COUNT(*) as alert_count,
        groupArray(body) as sample_logs
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND resources_string['host.name'] = 'ntopng'
      AND attributes_string['ntopng.alert_type'] IS NOT NULL
    GROUP BY alert_type, severity
    ORDER BY alert_count DESC
    LIMIT 5
    FORMAT JSONEachRow
    """

    try:
        # Execute queries
        pfsense_result = _execute_clickhouse_query(pfsense_query)
        ntopng_result = _execute_clickhouse_query(ntopng_query)

        # Parse results
        pfsense_threats = [json.loads(line) for line in pfsense_result.split('\n') if line]
        ntopng_alerts = [json.loads(line) for line in ntopng_result.split('\n') if line]

        # Build summary
        summary = {
            "time_range": f"last {hours} hour(s)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "firewall_blocks": {
                "total_unique_attackers": len(pfsense_threats),
                "top_threats": [
                    {
                        "src_ip": t['src_ip'],
                        "block_count": t['block_count'],
                        "target_port": t['dst_port'],
                        "protocol": t['protocol'],
                        "first_seen": _format_timestamp(t['first_seen']),
                        "last_seen": _format_timestamp(t['last_seen']),
                        "sample_logs": t['sample_logs'][:3]  # Only first 3 samples
                    }
                    for t in pfsense_threats[:5]  # Top 5 only
                ]
            },
            "ntopng_alerts": {
                "total_alert_types": len(ntopng_alerts),
                "alerts_by_type": [
                    {
                        "type": a['alert_type'],
                        "severity": a['severity'],
                        "count": a['alert_count'],
                        "sample_logs": a['sample_logs'][:2]  # Only 2 samples
                    }
                    for a in ntopng_alerts
                ]
            }
        }

        return json.dumps(summary, indent=2)

    except Exception as e:
        return f"Error querying security logs: {str(e)}"


@tool
def query_wireless_health(hours: int = 6) -> str:
    """Get wireless network health summary from UniFi logs.

    Args:
        hours: Lookback period in hours (default: 6, max: 24)

    Returns:
        JSON with auth failures, roaming events, and client issues
    """
    hours = min(hours, 24)

    query = f"""
    SELECT
        attributes_string['unifi.event'] as event_type,
        COUNT(*) as event_count,
        COUNT(DISTINCT resources_string['host.name']) as unique_aps,
        groupArray(body) as sample_logs
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND resources_string['device.type'] = 'access-point'
      AND attributes_string['unifi.event'] IN ('deauthenticated', 'disassociated', 'client_anomaly', 'ageout')
    GROUP BY event_type
    ORDER BY event_count DESC
    FORMAT JSONEachRow
    """

    try:
        result = _execute_clickhouse_query(query)
        events = [json.loads(line) for line in result.split('\n') if line]

        summary = {
            "time_range": f"last {hours} hour(s)",
            "wireless_events": [
                {
                    "event_type": e['event_type'],
                    "count": e['event_count'],
                    "affected_aps": e['unique_aps'],
                    "sample_logs": e['sample_logs'][:3]
                }
                for e in events
            ]
        }

        return json.dumps(summary, indent=2)

    except Exception as e:
        return f"Error querying wireless logs: {str(e)}"


@tool
def query_infrastructure_events(hours: int = 24) -> str:
    """Get infrastructure health events (Docker, HA, Proxmox).

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        JSON with container health, HA errors, VM operations
    """
    hours = min(hours, 24)

    # Docker health check failures
    docker_query = f"""
    SELECT
        COUNT(*) as health_check_failures,
        groupArray(body) as sample_logs
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND resources_string['host.name'] = 'docker'
      AND attributes_string['docker.event_type'] = 'health_check_failed'
    FORMAT JSONEachRow
    """

    # Home Assistant errors
    ha_query = f"""
    SELECT
        attributes_string['ha.service'] as service,
        COUNT(*) as error_count,
        groupArray(body) as sample_logs
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND resources_string['host.name'] = 'ha'
      AND attributes_string['ha.level'] = 'error'
    GROUP BY service
    ORDER BY error_count DESC
    LIMIT 5
    FORMAT JSONEachRow
    """

    # Proxmox VM operations
    proxmox_query = f"""
    SELECT
        attributes_string['proxmox.task'] as task,
        attributes_string['proxmox.status'] as status,
        COUNT(*) as operation_count
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND resources_string['device.type'] = 'hypervisor'
      AND attributes_string['proxmox.task'] IS NOT NULL
    GROUP BY task, status
    ORDER BY operation_count DESC
    FORMAT JSONEachRow
    """

    try:
        docker_result = _execute_clickhouse_query(docker_query)
        ha_result = _execute_clickhouse_query(ha_query)
        proxmox_result = _execute_clickhouse_query(proxmox_query)

        docker_data = [json.loads(line) for line in docker_result.split('\n') if line]
        ha_data = [json.loads(line) for line in ha_result.split('\n') if line]
        proxmox_data = [json.loads(line) for line in proxmox_result.split('\n') if line]

        summary = {
            "time_range": f"last {hours} hour(s)",
            "docker_health": {
                "failed_health_checks": docker_data[0]['health_check_failures'] if docker_data else 0,
                "sample_logs": docker_data[0]['sample_logs'][:3] if docker_data else []
            },
            "home_assistant_errors": [
                {
                    "service": e['service'],
                    "error_count": e['error_count'],
                    "sample_logs": e['sample_logs'][:2]
                }
                for e in ha_data
            ],
            "proxmox_operations": proxmox_data
        }

        return json.dumps(summary, indent=2)

    except Exception as e:
        return f"Error querying infrastructure logs: {str(e)}"


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@tool
def search_logs_by_ip(
    ip_address: str,
    hours: int = 24,
    source_types: Optional[List[str]] = None
) -> str:
    """Search all logs for a specific IP address.

    Args:
        ip_address: IP address to search for
        hours: Lookback period in hours (default: 24)
        source_types: Optional list of sources to search (filterlog, ntopng, etc.)

    Returns:
        JSON with all log entries mentioning this IP
    """
    if not _IP_RE.match(ip_address):
        return json.dumps({"error": f"Invalid IP address: {ip_address}"})

    hours = min(hours, 24)

    # Use ClickHouse {name:Type} parameter substitution to prevent injection.
    # positionCaseInsensitive avoids LIKE with user-supplied wildcards.
    query = f"""
    SELECT
        resources_string['service.name'] as source,
        COUNT(*) as mention_count,
        MIN(timestamp) as first_seen,
        MAX(timestamp) as last_seen,
        groupArray(body) as sample_logs
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND (
        positionCaseInsensitive(body, {{ip:String}}) > 0
        OR attributes_string['pfsense.src_ip'] = {{ip:String}}
        OR attributes_string['pfsense.dst_ip'] = {{ip:String}}
      )
    GROUP BY source
    ORDER BY mention_count DESC
    FORMAT JSONEachRow
    """

    try:
        result = _execute_clickhouse_query(query, {"ip": ip_address})
        mentions = [json.loads(line) for line in result.split('\n') if line]

        summary = {
            "ip_address": ip_address,
            "time_range": f"last {hours} hour(s)",
            "total_mentions": sum(m['mention_count'] for m in mentions),
            "sources": [
                {
                    "source": m['source'],
                    "mention_count": m['mention_count'],
                    "first_seen": _format_timestamp(m['first_seen']),
                    "last_seen": _format_timestamp(m['last_seen']),
                    "sample_logs": m['sample_logs'][:5]
                }
                for m in mentions
            ]
        }

        return json.dumps(summary, indent=2)

    except Exception as e:
        return f"Error searching logs for IP {ip_address}: {str(e)}"


def _execute_clickhouse_query(query: str, query_params: Optional[dict] = None) -> str:
    """Execute a ClickHouse query via HTTP.

    Args:
        query: SQL query, optionally with {name:Type} placeholders.
        query_params: Dict of substitution values; each key 'foo' maps to
                      HTTP param 'param_foo' per ClickHouse HTTP interface spec.
    """
    config = get_config()

    # ClickHouse HTTP interface (port 8123 by default)
    clickhouse_url = f"http://{config.signoz_clickhouse_host}:8123"

    params: dict = {
        "user": config.signoz_clickhouse_user,
        "password": config.signoz_clickhouse_password,
        "query": query,
    }
    if query_params:
        for k, v in query_params.items():
            params[f"param_{k}"] = v

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(clickhouse_url, params=params)

            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code} - {response.text}")

            return response.text.strip()

    except httpx.TimeoutException:
        raise Exception("Query timed out after 30 seconds")
    except Exception as e:
        raise Exception(f"ClickHouse query error: {str(e)}")


def _format_timestamp(ts_nano: int) -> str:
    """Convert nanosecond timestamp to ISO format."""
    try:
        ts_seconds = ts_nano / 1000000000
        return datetime.fromtimestamp(ts_seconds, tz=timezone.utc).isoformat()
    except Exception:
        return str(ts_nano)
