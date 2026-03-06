"""
Tools for querying and analyzing logs from SigNoz/ClickHouse.

Returns summaries for LLM analysis + sample log details for investigation.
"""

import subprocess
import json
from typing import Literal, Optional, Dict, List
from datetime import datetime

from langchain_core.tools import tool


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
            "timestamp": datetime.utcnow().isoformat(),
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
def query_adguard_anomalies(
    hours: int = 24,
    min_severity: str = "low"
) -> str:
    """Get AdGuard DNS security anomalies from analytics engine.

    Args:
        hours: Lookback period in hours (default: 24, max: 168)
        min_severity: Minimum severity to include (low, medium, high, critical)

    Returns:
        JSON with anomaly details, affected clients, and patterns
    """
    hours = min(hours, 168)  # Max 1 week

    # Map severity levels to filter
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_level = severity_order.get(min_severity.lower(), 0)
    severity_filter = "'" + "','".join([s for s, l in severity_order.items() if l >= min_level]) + "'"

    query = f"""
    SELECT
        attributes_string['anomaly.type'] as anomaly_type,
        attributes_string['anomaly.severity'] as severity,
        attributes_string['anomaly.client_ip'] as client_ip,
        attributes_string['anomaly.domain'] as domain,
        attributes_number['anomaly.confidence'] as confidence,
        COUNT(*) as occurrence_count,
        MIN(timestamp) as first_detected,
        MAX(timestamp) as last_detected,
        groupArray(body) as sample_descriptions
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND attributes_string['anomaly.type'] IS NOT NULL
      AND attributes_string['anomaly.severity'] IN ({severity_filter})
    GROUP BY anomaly_type, severity, client_ip, domain, confidence
    ORDER BY
        CASE severity
            WHEN 'critical' THEN 4
            WHEN 'high' THEN 3
            WHEN 'medium' THEN 2
            ELSE 1
        END DESC,
        occurrence_count DESC
    LIMIT 50
    FORMAT JSONEachRow
    """

    try:
        result = _execute_clickhouse_query(query)

        if not result:
            return json.dumps({
                "time_range": f"last {hours} hour(s)",
                "min_severity": min_severity,
                "total_anomalies": 0,
                "anomalies": []
            }, indent=2)

        anomalies = [json.loads(line) for line in result.split('\n') if line]

        # Group by type for summary
        by_type = {}
        for a in anomalies:
            atype = a['anomaly_type']
            if atype not in by_type:
                by_type[atype] = {
                    "type": atype,
                    "total_occurrences": 0,
                    "unique_clients": set(),
                    "severities": {},
                    "examples": []
                }
            # Convert to int in case it comes back as string
            occ_count = int(a['occurrence_count'])
            by_type[atype]["total_occurrences"] += occ_count
            by_type[atype]["unique_clients"].add(a['client_ip'])
            severity = a['severity']
            by_type[atype]["severities"][severity] = by_type[atype]["severities"].get(severity, 0) + occ_count

            # Add example if < 3
            if len(by_type[atype]["examples"]) < 3:
                by_type[atype]["examples"].append({
                    "client_ip": a['client_ip'],
                    "domain": a['domain'],
                    "confidence": a['confidence'],
                    "severity": a['severity'],
                    "first_detected": _format_timestamp(a['first_detected']),
                    "last_detected": _format_timestamp(a['last_detected']),
                    "description": a['sample_descriptions'][0] if a['sample_descriptions'] else None
                })

        # Convert sets to counts for JSON serialization
        summary = {
            "time_range": f"last {hours} hour(s)",
            "min_severity": min_severity,
            "total_anomalies": len(anomalies),
            "total_occurrences": sum(int(a['occurrence_count']) for a in anomalies),
            "anomalies_by_type": [
                {
                    "type": data["type"],
                    "total_occurrences": data["total_occurrences"],
                    "unique_clients": len(data["unique_clients"]),
                    "severities": data["severities"],
                    "examples": data["examples"]
                }
                for data in sorted(by_type.values(), key=lambda x: x["total_occurrences"], reverse=True)
            ]
        }

        return json.dumps(summary, indent=2)

    except Exception as e:
        return f"Error querying AdGuard anomalies: {str(e)}"


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
    hours = min(hours, 24)

    # Search in body and attributes
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
        body LIKE '%{ip_address}%'
        OR attributes_string['pfsense.src_ip'] = '{ip_address}'
        OR attributes_string['pfsense.dst_ip'] = '{ip_address}'
      )
    GROUP BY source
    ORDER BY mention_count DESC
    FORMAT JSONEachRow
    """

    try:
        result = _execute_clickhouse_query(query)
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


def _execute_clickhouse_query(query: str) -> str:
    """Execute a ClickHouse query via Docker."""
    try:
        result = subprocess.run(
            ["docker", "exec", "signoz-clickhouse", "clickhouse-client", "-q", query],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise Exception(f"Query failed: {result.stderr}")

        return result.stdout.strip()

    except subprocess.TimeoutExpired:
        raise Exception("Query timed out after 30 seconds")
    except Exception as e:
        raise Exception(f"ClickHouse query error: {str(e)}")


def _format_timestamp(ts_nano: int) -> str:
    """Convert nanosecond timestamp to ISO format."""
    try:
        ts_seconds = ts_nano / 1000000000
        return datetime.utcfromtimestamp(ts_seconds).isoformat() + "Z"
    except:
        return str(ts_nano)
