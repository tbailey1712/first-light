"""
Tools for querying metrics from SigNoz/ClickHouse.
"""

import subprocess
from typing import Literal, Optional

from langchain_core.tools import tool

from agent.config import get_config


@tool
def query_adguard_top_clients(
    hours: int = 24,
    limit: int = 20
) -> str:
    """Get top DNS clients by query volume.

    Args:
        hours: Lookback period in hours (default: 24)
        limit: Number of results to return (default: 20)

    Returns:
        Formatted table of top clients with query counts
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'client.name') as client,
            simpleJSONExtractString(ts.labels, 'client.ip') as ip,
            sum(s.value) as total_queries
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard.queries.total'
          AND s.unix_milli > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000
        GROUP BY client, ip
        ORDER BY total_queries DESC
        LIMIT {limit}
    """

    return _execute_clickhouse_query(query)


@tool
def query_adguard_block_rates(
    hours: int = 24,
    min_block_rate: float = 0.0,
    limit: int = 20
) -> str:
    """Get DNS block rates per client.

    Args:
        hours: Lookback period in hours (default: 24)
        min_block_rate: Minimum block rate to include (0-100, default: 0)
        limit: Number of results to return (default: 20)

    Returns:
        Formatted table of clients with their block rates
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'client.name') as client,
            simpleJSONExtractString(ts.labels, 'client.ip') as ip,
            round(avg(s.value), 2) as avg_block_rate
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard.block.rate'
          AND s.unix_milli > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000
        GROUP BY client, ip
        HAVING avg_block_rate >= {min_block_rate}
        ORDER BY avg_block_rate DESC
        LIMIT {limit}
    """

    return _execute_clickhouse_query(query)


@tool
def query_adguard_high_risk_clients(
    hours: int = 24,
    min_risk_score: float = 5.0
) -> str:
    """Get clients with elevated risk scores.

    Args:
        hours: Lookback period in hours (default: 24)
        min_risk_score: Minimum risk score to include (0-10, default: 5.0)

    Returns:
        Formatted table of high-risk clients
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'client.name') as client,
            simpleJSONExtractString(ts.labels, 'client.ip') as ip,
            round(avg(s.value), 2) as risk_score
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard.client.risk_score'
          AND s.unix_milli > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000
        GROUP BY client, ip
        HAVING risk_score >= {min_risk_score}
        ORDER BY risk_score DESC
    """

    return _execute_clickhouse_query(query)


@tool
def query_adguard_blocked_domains(
    hours: int = 24,
    limit: int = 20
) -> str:
    """Get top blocked domains.

    Args:
        hours: Lookback period in hours (default: 24)
        limit: Number of results to return (default: 20)

    Returns:
        Formatted table of most blocked domains
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'domain') as domain,
            sum(s.value) as total_blocks,
            simpleJSONExtractString(ts.labels, 'unique_clients') as unique_clients
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard.blocked_domains.total'
          AND s.unix_milli > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000
        GROUP BY domain, unique_clients
        ORDER BY total_blocks DESC
        LIMIT {limit}
    """

    return _execute_clickhouse_query(query)


@tool
def query_adguard_traffic_by_type(hours: int = 24) -> str:
    """Get DNS query volume by traffic type (user vs automated).

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        Formatted table showing user vs automated traffic patterns
    """
    query = f"""
        SELECT
            simpleJSONExtractString(ts.labels, 'traffic.type') as traffic_type,
            sum(s.value) as total_queries,
            count(DISTINCT simpleJSONExtractString(ts.labels, 'client.ip')) as unique_clients
        FROM signoz_metrics.samples_v4 s
        JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
        WHERE s.metric_name = 'adguard.queries.total'
          AND s.unix_milli > toUnixTimestamp(now() - INTERVAL {hours} HOUR) * 1000
        GROUP BY traffic_type
        ORDER BY total_queries DESC
    """

    return _execute_clickhouse_query(query)


def _execute_clickhouse_query(query: str) -> str:
    """Execute a ClickHouse query via Docker and return results.

    Args:
        query: SQL query to execute

    Returns:
        Query results as formatted string
    """
    try:
        # Use remote Docker context to execute on docker host
        result = subprocess.run(
            ["docker", "exec", "signoz-clickhouse", "clickhouse-client", "-q", query],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return f"Error executing query: {result.stderr}"

        if not result.stdout.strip():
            return "No results found"

        return result.stdout.strip()

    except subprocess.TimeoutExpired:
        return "Query timed out after 30 seconds"
    except Exception as e:
        return f"Error: {str(e)}"
