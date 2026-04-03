"""
Tools for querying AdGuard DNS analytics metrics from SigNoz/ClickHouse.

The AdGuard analytics exporter (v2) scrapes https://adguard.mcducklabs.com:3001/metrics
every ~60s. Metrics are stored in ClickHouse with underscore names (adguard_*) and
underscore label names (client_ip, client_name, traffic_type, etc.).

Typical daily profile: ~65k queries, ~8% block rate, ~90 active clients, 47 DHCP devices.
"""

import httpx
from typing import Literal, Optional

from langchain_core.tools import tool

from agent.config import get_config
from agent.utils.resolve import enrich_ip_column


# ─────────────────────────────────────────────────────
# Core client traffic tools
# ─────────────────────────────────────────────────────

@tool
def query_adguard_top_clients(hours: int = 24, limit: int = 20) -> str:
    """Get top DNS clients by query volume.

    Args:
        hours: Lookback period in hours (default: 24)
        limit: Number of results (default: 20)

    Returns:
        Tab-separated table: client_name, client_ip, traffic_type, total_queries
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'client_name') as client,
            simpleJSONExtractString(ts.labels, 'client_ip') as ip,
            simpleJSONExtractString(ts.labels, 'traffic_type') as traffic_type,
            round(avg(s.value), 0) as queries_24h
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard_client_queries_24h'
          AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
        GROUP BY client, ip, traffic_type
        ORDER BY queries_24h DESC
        LIMIT {limit}
    """
    return _execute_clickhouse_query(query)


@tool
def query_adguard_block_rates(
    hours: int = 24,
    min_block_rate: float = 0.0,
    limit: int = 20,
) -> str:
    """Get DNS block rates per client.

    Args:
        hours: Lookback period in hours (default: 24)
        min_block_rate: Minimum block rate % to include (default: 0)
        limit: Number of results (default: 20)

    Returns:
        Tab-separated table: client_name, client_ip, avg_block_rate_%
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'client_name') as client,
            simpleJSONExtractString(ts.labels, 'client_ip') as ip,
            round(avg(s.value), 2) as avg_block_rate_pct
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard_client_block_rate'
          AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
        GROUP BY client, ip
        HAVING avg_block_rate_pct >= {min_block_rate}
        ORDER BY avg_block_rate_pct DESC
        LIMIT {limit}
    """
    return _execute_clickhouse_query(query)


@tool
def query_adguard_high_risk_clients(
    hours: int = 24,
    min_risk_score: float = 5.0,
) -> str:
    """Get clients with elevated risk scores.

    Risk score 0-10, derived from block rate and anomaly signals.
    Score >= 7 = high risk; 5-7 = medium risk.

    Args:
        hours: Lookback period in hours (default: 24)
        min_risk_score: Minimum score to include (default: 5.0)

    Returns:
        Tab-separated table: client_name, client_ip, risk_score
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'client_name') as client,
            simpleJSONExtractString(ts.labels, 'client_ip') as ip,
            round(avg(s.value), 2) as risk_score
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard_client_risk_score'
          AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
        GROUP BY client, ip
        HAVING risk_score >= {min_risk_score}
        ORDER BY risk_score DESC
    """
    return _execute_clickhouse_query(query)


@tool
def query_adguard_traffic_by_type(hours: int = 24) -> str:
    """Get DNS query volume split by traffic type (user vs automated).

    Traffic type classification:
    - user: < 10K queries/day — manual/interactive traffic
    - automated: >= 10K queries/day — background/IoT polling
    - inactive: no recent activity

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        Tab-separated table: traffic_type, total_queries, unique_clients
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'traffic_type') as traffic_type,
            round(sum(s.value), 0) as total_queries,
            count(DISTINCT simpleJSONExtractString(ts.labels, 'client_ip')) as unique_clients
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard_client_queries_24h'
          AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
        GROUP BY traffic_type
        ORDER BY total_queries DESC
    """
    return _execute_clickhouse_query(query)


# ─────────────────────────────────────────────────────
# Network summary
# ─────────────────────────────────────────────────────

@tool
def query_adguard_network_summary(hours: int = 24) -> str:
    """Get aggregate DNS network stats: totals, block rate, anomaly counts.

    Covers: total queries/blocks, overall block %, unacknowledged anomalies by
    severity, top DHCP device count. Use this as the starting point for DNS
    security analysis.

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        Tab-separated tables of aggregate stats and anomaly summary
    """
    queries = {
        "totals": f"""
            SELECT
                metric_name,
                round(avg(s.value), 1) as value
            FROM signoz_metrics.samples_v4 s
            WHERE metric_name IN (
                'adguard_queries_total',
                'adguard_blocks_total',
                'adguard_block_rate_total',
                'adguard_dhcp_active_devices'
            )
            AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
            GROUP BY metric_name
            ORDER BY metric_name
        """,
        "anomalies_by_severity": f"""
            SELECT
                simpleJSONExtractString(ts.labels, 'severity') as severity,
                round(avg(s.value), 0) as unacknowledged_count
            FROM signoz_metrics.samples_v4 s
            JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
            WHERE s.metric_name = 'adguard_anomalies_unacknowledged'
              AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
            GROUP BY severity
            ORDER BY severity
        """,
    }
    results = []
    for label, query in queries.items():
        result = _execute_clickhouse_query(query)
        results.append(f"=== {label} ===\n{result}")
    return "\n\n".join(results)


# ─────────────────────────────────────────────────────
# DHCP device fingerprinting
# ─────────────────────────────────────────────────────

@tool
def query_adguard_dhcp_fingerprints(hours: int = 24) -> str:
    """Get DHCP device fingerprinting data: top domains per device for identification.

    DHCP devices are unidentified (IPs in 192.168.1.200-.245 or 192.168.2.100-.199).
    Top domains reveal device type:
    - ring.com, fw.ring.com → Ring camera/doorbell
    - meethue.com, dcp.cpp.philips.com → Hue bridge
    - shelly.cloud, shellies.io → Shelly smart plug
    - amazon.com, audible.com → Echo/Alexa
    High unique domain count (50+) suggests a general-purpose computer, not IoT.
    Very low unique domains (2-5) suggests constrained IoT sensor.

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        Tab-separated table: client_ip, total_queries, top domains across all DHCP devices
    """
    queries = {
        "dhcp_device_query_volumes": f"""
            SELECT
                simpleJSONExtractString(ts.labels, 'client_ip') as client_ip,
                simpleJSONExtractString(ts.labels, 'client_name') as client_name,
                round(avg(s.value), 0) as queries_24h
            FROM signoz_metrics.samples_v4 s
            JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
            WHERE s.metric_name = 'adguard_dhcp_device_queries_24h'
              AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
            GROUP BY client_ip, client_name
            ORDER BY queries_24h DESC
        """,
        "top_domains_across_dhcp": f"""
            SELECT
                simpleJSONExtractString(ts.labels, 'base_domain') as base_domain,
                simpleJSONExtractString(ts.labels, 'client_count') as client_count,
                round(avg(s.value), 0) as query_count
            FROM signoz_metrics.samples_v4 s
            JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
            WHERE s.metric_name = 'adguard_dhcp_top_domain_queries_24h'
              AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
            GROUP BY base_domain, client_count
            ORDER BY query_count DESC
            LIMIT 30
        """,
    }
    results = []
    for label, query in queries.items():
        result = _execute_clickhouse_query(query)
        results.append(f"=== {label} ===\n{result}")
    return "\n\n".join(results)


# ─────────────────────────────────────────────────────
# Threat detection signals
# ─────────────────────────────────────────────────────

@tool
def query_adguard_threat_signals(hours: int = 24) -> str:
    """Get DNS-based threat detection signals: anomalies, blocked domain persistence, and ingestion health.

    Covers the threat signals that ARE populated in the current exporter:
    - Unacknowledged anomalies by severity (statistical, entropy, temporal, etc.)
    - Top blocked domains being repeatedly attempted across all clients

    Note: Advanced signals (beaconing scores, TXT ratios, per-client anomaly counts,
    new domain tracking) are defined in the exporter but require security_stats
    ingestion to populate. Check adguard_ingestion_last_duration_seconds to verify
    the ingestion pipeline is running.

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        Anomaly counts and blocked domain persistence data
    """
    queries = {
        "anomaly_counts_by_severity": f"""
            SELECT
                simpleJSONExtractString(ts.labels, 'severity') as severity,
                round(avg(s.value), 0) as count
            FROM signoz_metrics.samples_v4 s
            JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
            WHERE s.metric_name = 'adguard_anomalies_unacknowledged'
              AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
            GROUP BY severity
            ORDER BY severity
        """,
        "ingestion_health": f"""
            SELECT
                metric_name,
                round(avg(s.value), 1) as value
            FROM signoz_metrics.samples_v4 s
            WHERE metric_name IN (
                'adguard_ingestion_last_duration_seconds',
                'adguard_db_visits_total',
                'adguard_db_size_bytes'
            )
            AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
            GROUP BY metric_name
        """,
        "ingestion_records": f"""
            SELECT
                simpleJSONExtractString(ts.labels, 'type') as record_type,
                round(avg(s.value), 0) as count
            FROM signoz_metrics.samples_v4 s
            JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
            WHERE s.metric_name = 'adguard_ingestion_last_records'
              AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
            GROUP BY record_type
        """,
    }
    results = []
    for label, query in queries.items():
        result = _execute_clickhouse_query(query)
        results.append(f"=== {label} ===\n{result}")
    return "\n\n".join(results)


@tool
def query_adguard_blocked_domains(
    hours: int = 24,
    limit: int = 20,
) -> str:
    """Get top clients by blocks and their block rates — reveals which devices are hitting blocked content most.

    Returns clients with the most blocked queries in descending order. Cross-reference
    with known device list: high block rates on personal devices (phones, laptops) may
    indicate ad blocking working normally. High blocks on IoT devices that normally
    query only 2-3 domains warrants investigation.

    Args:
        hours: Lookback period in hours (default: 24)
        limit: Number of results (default: 20)

    Returns:
        Tab-separated table: client_name, client_ip, blocks_24h, block_rate_%
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'client_name') as client,
            simpleJSONExtractString(ts.labels, 'client_ip') as ip,
            simpleJSONExtractString(ts.labels, 'traffic_type') as traffic_type,
            round(avg(s.value), 0) as blocks_24h
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard_client_blocks_24h'
          AND s.unix_milli > (toUnixTimestamp(now()) - {hours} * 3600) * 1000
          AND s.value > 0
        GROUP BY client, ip, traffic_type
        ORDER BY blocks_24h DESC
        LIMIT {limit}
    """
    return _execute_clickhouse_query(query)


# ─────────────────────────────────────────────────────
# Internal helper
# ─────────────────────────────────────────────────────

def _execute_clickhouse_query(query: str) -> str:
    """Execute a ClickHouse query via HTTP and return tab-separated results."""
    config = get_config()
    clickhouse_url = f"http://{config.signoz_clickhouse_host}:8123"

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                clickhouse_url,
                params={
                    "user": config.signoz_clickhouse_user,
                    "password": config.signoz_clickhouse_password,
                    "query": query,
                }
            )
            if response.status_code != 200:
                return f"Error: HTTP {response.status_code} — {response.text[:200]}"
            result = response.text.strip()
            if not result:
                return "No results found"
            return enrich_ip_column(result)
    except httpx.TimeoutException:
        return "Query timed out after 30 seconds"
    except Exception as e:
        return f"Error: {e}"
