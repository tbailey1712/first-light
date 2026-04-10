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
    FROM signoz_logs.distributed_logs_v2
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
    FROM signoz_logs.distributed_logs_v2
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
    """Get wireless network health summary from UniFi AP syslog events.

    Covers: deauthentication, disassociation, roaming, sta_unauthorized,
    and notable events (unusual reason codes). Uses unifi.event_type attribute
    set by the OTel transform/unifi processor.

    Args:
        hours: Lookback period in hours (default: 6, max: 48)

    Returns:
        JSON with event counts per type per AP, notable events, and samples
    """
    hours = min(hours, 48)

    # Security-relevant and notable wireless events by type
    event_query = f"""
    SELECT
        attributes_string['unifi.event_type'] as event_type,
        attributes_string['unifi.ap_hostname'] as ap_hostname,
        COUNT(*) as event_count,
        COUNT(DISTINCT attributes_string['unifi.client_mac']) as unique_clients,
        groupArray(10)(body) as sample_logs
    FROM signoz_logs.distributed_logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND resources_string['device.type'] = 'access-point'
      AND attributes_string['unifi.event_type'] IN (
          'deauthentication', 'disassociation', 'sta_unauthorized',
          'roaming', 'association', 'reassociation'
      )
    GROUP BY event_type, ap_hostname
    ORDER BY event_count DESC
    LIMIT 50
    FORMAT JSONEachRow
    """

    # Events flagged as notable by the OTel parser (unusual reason codes, etc.)
    notable_query = f"""
    SELECT
        attributes_string['unifi.event_type'] as event_type,
        attributes_string['unifi.ap_hostname'] as ap,
        attributes_string['unifi.client_mac'] as client_mac,
        attributes_string['unifi.reason_code'] as reason_code,
        attributes_string['unifi.signal_dbm'] as signal_dbm,
        body
    FROM signoz_logs.distributed_logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND resources_string['device.type'] = 'access-point'
      AND attributes_string['unifi.notable'] = 'true'
    ORDER BY timestamp DESC
    LIMIT 20
    FORMAT JSONEachRow
    """

    # STA_ASSOC_TRACKER auth failures — JSON-in-syslog that the OTel parser
    # doesn't extract attributes from. Parse mac directly from body.
    # Groups by MAC to identify persistent offenders (stale PSK, wrong password).
    auth_fail_query = f"""
    SELECT
        extract(body, '"mac":"([^"]+)"') as mac,
        COUNT(*) as total_failures,
        COUNT(DISTINCT resources_string['host.name']) as ap_count,
        groupUniqArray(resources_string['host.name']) as aps_seen,
        min(timestamp) as first_seen,
        max(timestamp) as last_seen
    FROM signoz_logs.distributed_logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND body LIKE '%STA_ASSOC_TRACKER%'
      AND body LIKE '%"event_type":"failure"%'
    GROUP BY mac
    HAVING total_failures > 5 AND mac != ''
    ORDER BY total_failures DESC
    LIMIT 20
    FORMAT JSONEachRow
    """

    try:
        events_raw = _execute_clickhouse_query(event_query)
        notable_raw = _execute_clickhouse_query(notable_query)
        auth_fail_raw = _execute_clickhouse_query(auth_fail_query)

        events = [json.loads(line) for line in events_raw.split('\n') if line.strip()]
        notables = [json.loads(line) for line in notable_raw.split('\n') if line.strip()]
        auth_fails = [json.loads(line) for line in auth_fail_raw.split('\n') if line.strip()]

        if not events and not notables and not auth_fails:
            return json.dumps({
                "time_range": f"last {hours}h",
                "status": "no_data",
                "note": "No UniFi AP event data found. APs may not be forwarding syslog to the collector (TCP 5140), or no notable wireless events occurred.",
                "wireless_events": [],
                "notable_events": [],
                "auth_failures": [],
            }, indent=2)

        # Summarise by event type across APs
        by_type: Dict[str, dict] = {}
        for e in events:
            et = e['event_type']
            if et not in by_type:
                by_type[et] = {"event_type": et, "total": 0, "per_ap": []}
            by_type[et]["total"] += int(e['event_count'])
            by_type[et]["per_ap"].append({
                "ap": e['ap_hostname'],
                "count": int(e['event_count']),
                "unique_clients": int(e['unique_clients']),
            })

        # Annotate auth failures: ap_count > 1 means device is roaming while
        # failing — strong indicator of stale/wrong PSK rather than a scanner.
        annotated_fails = []
        for f in auth_fails:
            annotated_fails.append({
                "mac": f["mac"],
                "total_failures": int(f["total_failures"]),
                "ap_count": int(f["ap_count"]),
                "aps_seen": f["aps_seen"],
                "first_seen": _format_timestamp(f["first_seen"]),
                "last_seen": _format_timestamp(f["last_seen"]),
                "likely_cause": (
                    "stale/wrong PSK — device is roaming while failing auth"
                    if int(f["ap_count"]) > 1
                    else "persistent auth failure on single AP"
                ),
            })

        return json.dumps({
            "time_range": f"last {hours}h",
            "status": "ok",
            "event_summary": sorted(by_type.values(), key=lambda x: x["total"], reverse=True),
            "notable_events": notables,
            "auth_failures": annotated_fails,
        }, indent=2, default=str)

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
    FROM signoz_logs.distributed_logs_v2
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
    FROM signoz_logs.distributed_logs_v2
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
    FROM signoz_logs.distributed_logs_v2
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
def query_auth_events(hours: int = 24) -> str:
    """Get SSH and sudo security events across all syslog-reporting hosts.

    Covers SSH brute force attempts, invalid user logins, successful logins
    from unexpected sources, and sudo privilege escalation events. Queries
    structured attributes set by the OTel ssh_sudo parser.

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        JSON with SSH failure summary by attacker IP/host, successful logins,
        and notable sudo activity.
    """
    hours = min(hours, 168)

    # SSH failures by attacking IP across all hosts
    ssh_failures_query = f"""
    SELECT
        attributes_string['ssh.source_ip'] as src_ip,
        resources_string['host.name'] as target_host,
        attributes_string['ssh.event'] as event,
        attributes_string['ssh.user'] as attempted_user,
        COUNT(*) as count,
        MAX(toDateTime(timestamp / 1000000000)) as last_seen
    FROM signoz_logs.distributed_logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND mapContains(attributes_string, 'ssh.event')
      AND attributes_string['ssh.event'] IN ('login_failure', 'invalid_user')
      AND length(attributes_string['ssh.source_ip']) > 0
    GROUP BY src_ip, target_host, event, attempted_user
    ORDER BY count DESC
    LIMIT 30
    FORMAT JSONEachRow
    """

    # Successful SSH logins — flag any from non-192.168.1.x (potentially external)
    ssh_success_query = f"""
    SELECT
        attributes_string['ssh.source_ip'] as src_ip,
        resources_string['host.name'] as target_host,
        attributes_string['ssh.user'] as user,
        attributes_string['ssh.auth_method'] as auth_method,
        COUNT(*) as count,
        MAX(toDateTime(timestamp / 1000000000)) as last_seen
    FROM signoz_logs.distributed_logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND mapContains(attributes_string, 'ssh.event')
      AND attributes_string['ssh.event'] = 'login_success'
      AND length(attributes_string['ssh.source_ip']) > 0
    GROUP BY src_ip, target_host, user, auth_method
    ORDER BY count DESC
    LIMIT 20
    FORMAT JSONEachRow
    """

    # Sudo activity — privilege escalation events
    sudo_query = f"""
    SELECT
        resources_string['host.name'] as host,
        attributes_string['sudo.user'] as user,
        attributes_string['sudo.event'] as event,
        attributes_string['sudo.command'] as command,
        COUNT(*) as count,
        MAX(toDateTime(timestamp / 1000000000)) as last_seen
    FROM signoz_logs.distributed_logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND mapContains(attributes_string, 'sudo.event')
    GROUP BY host, user, event, command
    ORDER BY count DESC
    LIMIT 20
    FORMAT JSONEachRow
    """

    try:
        failures_raw = _execute_clickhouse_query(ssh_failures_query)
        success_raw = _execute_clickhouse_query(ssh_success_query)
        sudo_raw = _execute_clickhouse_query(sudo_query)

        failures = [json.loads(l) for l in failures_raw.split('\n') if l.strip()]
        successes = [json.loads(l) for l in success_raw.split('\n') if l.strip()]
        sudo_events = [json.loads(l) for l in sudo_raw.split('\n') if l.strip()]

        # Flag successful logins from outside trusted LAN (192.168.1.x)
        external_logins = [
            s for s in successes
            if not s.get("src_ip", "").startswith("192.168.1.")
        ]

        total_failures = sum(int(f["count"]) for f in failures)
        unique_attackers = len({f["src_ip"] for f in failures})

        return json.dumps({
            "time_range": f"last {hours}h",
            "ssh_brute_force": {
                "total_failed_attempts": total_failures,
                "unique_attacker_ips": unique_attackers,
                "top_attackers": [
                    {
                        "src_ip": f["src_ip"],
                        "target_host": f["target_host"],
                        "event": f["event"],
                        "attempted_user": f["attempted_user"],
                        "count": f["count"],
                        "last_seen": str(f["last_seen"]),
                    }
                    for f in failures[:15]
                ],
            },
            "ssh_successful_logins": [
                {
                    "src_ip": s["src_ip"],
                    "target_host": s["target_host"],
                    "user": s["user"],
                    "auth_method": s["auth_method"],
                    "count": s["count"],
                    "last_seen": str(s["last_seen"]),
                    "flag": "EXTERNAL_SOURCE" if s in external_logins else "ok",
                }
                for s in successes
            ],
            "external_logins_flag": len(external_logins),
            "sudo_activity": [
                {
                    "host": e["host"],
                    "user": e["user"],
                    "event": e["event"],
                    "command": e["command"],
                    "count": e["count"],
                    "last_seen": str(e["last_seen"]),
                }
                for e in sudo_events
            ],
        }, indent=2)

    except Exception as e:
        return f"Error querying auth events: {str(e)}"


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
    FROM signoz_logs.distributed_logs_v2
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
            "total_mentions": sum(int(m['mention_count']) for m in mentions),
            "sources": [
                {
                    "source": m['source'],
                    "mention_count": int(m['mention_count']),
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


@tool
def query_outbound_blocks(hours: int = 24) -> str:
    """Get pfSense firewall blocks where internal hosts are the source (outbound blocks).

    These are blocks where a device on the LAN/IoT/CCTV/DMZ network tried to reach
    an external destination and was blocked by pfSense policy. This is a strong signal
    of potentially compromised or misconfigured internal devices — legitimate internal
    hosts generally do not get outbound-blocked unless they are:
    - Trying to reach a blocked category (malware C2, ads via DNS-based rules)
    - Violating VLAN egress policy (e.g., VLAN2 IoT trying to reach VLAN1)
    - Infected and attempting to reach known bad IPs

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        JSON with top internal IPs that triggered outbound blocks, their destination
        IPs/ports, and block counts.
    """
    hours = min(hours, 48)

    query = f"""
    SELECT
        attributes_string['pfsense.src_ip'] as src_ip,
        attributes_string['pfsense.dst_ip'] as dst_ip,
        attributes_string['pfsense.dst_port'] as dst_port,
        attributes_string['pfsense.protocol'] as protocol,
        attributes_string['pfsense.interface'] as interface,
        COUNT(*) as block_count,
        MIN(toDateTime(timestamp / 1000000000)) as first_seen,
        MAX(toDateTime(timestamp / 1000000000)) as last_seen
    FROM signoz_logs.distributed_logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND resources_string['service.name'] = 'filterlog'
      AND attributes_string['pfsense.action'] = 'block'
      AND attributes_string['pfsense.direction'] = 'out'
      AND (
        attributes_string['pfsense.src_ip'] LIKE '192.168.%'
        OR attributes_string['pfsense.src_ip'] LIKE '10.%'
        OR attributes_string['pfsense.src_ip'] LIKE '172.16.%'
      )
      AND attributes_string['pfsense.src_ip'] != ''
    GROUP BY src_ip, dst_ip, dst_port, protocol, interface
    ORDER BY block_count DESC
    LIMIT 25
    FORMAT JSONEachRow
    """

    try:
        raw = _execute_clickhouse_query(query)
        rows = [json.loads(line) for line in raw.split('\n') if line.strip()]

        if not rows:
            return json.dumps({"time_range": f"last {hours}h", "outbound_blocks": [], "summary": "No outbound blocks found — all internal hosts behaving normally"})

        # Group by source IP for a cleaner per-device view
        by_src: Dict[str, dict] = {}
        for row in rows:
            src = row["src_ip"]
            if src not in by_src:
                by_src[src] = {
                    "src_ip": src,
                    "total_blocks": 0,
                    "destinations": [],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                }
            by_src[src]["total_blocks"] += row["block_count"]
            by_src[src]["destinations"].append({
                "dst_ip": row["dst_ip"],
                "dst_port": row["dst_port"],
                "protocol": row["protocol"],
                "interface": row["interface"],
                "count": row["block_count"],
            })
            # Track widest time window
            if str(row["first_seen"]) < str(by_src[src]["first_seen"]):
                by_src[src]["first_seen"] = row["first_seen"]
            if str(row["last_seen"]) > str(by_src[src]["last_seen"]):
                by_src[src]["last_seen"] = row["last_seen"]

        sources = sorted(by_src.values(), key=lambda x: x["total_blocks"], reverse=True)

        return json.dumps({
            "time_range": f"last {hours}h",
            "unique_internal_sources": len(sources),
            "total_outbound_blocks": sum(s["total_blocks"] for s in sources),
            "outbound_blocks": sources[:15],
        }, indent=2, default=str)

    except Exception as e:
        return f"Error querying outbound blocks: {str(e)}"


_HOSTNAME_SAFE_RE = re.compile(r"[^a-zA-Z0-9.\-_]")


@tool
def search_logs_by_hostname(
    hostname: str,
    hours: int = 24,
    limit: int = 50,
) -> str:
    """Search logs by hostname or service name across all sources.

    Useful for investigating a specific device flagged in the report — returns recent
    log entries from that host regardless of source.

    Args:
        hostname: Hostname or service name to search for (e.g. "pve", "caddy", "adguard")
        hours: Lookback window in hours (default: 24)
        limit: Maximum number of rows to return (default: 50)

    Returns:
        JSON with total match count and a list of log entries including timestamp,
        body, severity, host.name, and service.name.
    """
    # Sanitize: keep only alphanumeric, dots, dashes, underscores to prevent injection
    safe_hostname = _HOSTNAME_SAFE_RE.sub("", hostname)
    if not safe_hostname:
        return json.dumps({"error": f"Invalid hostname after sanitization: {hostname!r}"})

    hours = min(hours, 168)
    limit = min(limit, 200)

    query = f"""
    SELECT
        toDateTime(timestamp / 1000000000) AS ts,
        body,
        severity_text,
        resources_string['host.name'] AS host_name,
        resources_string['service.name'] AS service_name
    FROM signoz_logs.distributed_logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000000000
      AND (
        resources_string['host.name'] ILIKE '%{safe_hostname}%'
        OR body ILIKE '%{safe_hostname}%'
        OR resources_string['service.name'] ILIKE '%{safe_hostname}%'
      )
    ORDER BY timestamp DESC
    LIMIT {limit}
    FORMAT JSONEachRow
    """

    try:
        raw = _execute_clickhouse_query(query)
        rows = [json.loads(line) for line in raw.split('\n') if line.strip()]

        return json.dumps({
            "hostname_query": safe_hostname,
            "time_range": f"last {hours}h",
            "total_returned": len(rows),
            "logs": [
                {
                    "timestamp": str(r.get("ts")),
                    "body": r.get("body"),
                    "severity": r.get("severity_text"),
                    "host_name": r.get("host_name"),
                    "service_name": r.get("service_name"),
                }
                for r in rows
            ],
        }, indent=2)

    except Exception as e:
        return f"Error searching logs for hostname {safe_hostname!r}: {str(e)}"


def _execute_clickhouse_query(
    query: str,
    query_params: Optional[dict] = None,
    ch_settings: Optional[dict] = None,
) -> str:
    """Execute a ClickHouse query via HTTP.

    Args:
        query: SQL query, optionally with {name:Type} placeholders.
        query_params: Dict of substitution values; each key 'foo' maps to
                      HTTP param 'param_foo' per ClickHouse HTTP interface spec.
        ch_settings: Optional ClickHouse server-side settings (e.g. max_result_rows).
    """
    config = get_config()

    # ClickHouse HTTP interface (port 8123 by default)
    clickhouse_url = f"http://{config.signoz_clickhouse_host}:8123"

    params: dict = {"query": query}
    if query_params:
        for k, v in query_params.items():
            params[f"param_{k}"] = v
    if ch_settings:
        params.update(ch_settings)

    headers = {
        "X-ClickHouse-User": config.signoz_clickhouse_user,
        "X-ClickHouse-Key": config.signoz_clickhouse_password,
    }

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(clickhouse_url, params=params, headers=headers)

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
