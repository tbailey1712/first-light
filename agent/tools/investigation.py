"""
Investigation tools for deep-dive incident analysis.

Provides a raw ClickHouse query tool for ad-hoc log investigation when
pre-built tools don't cover the specific query needed.
"""

import json
import logging
import re

from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# Allowed tables for raw queries — prevents the agent from touching other data
_ALLOWED_TABLES = {"signoz_logs.logs_v2", "threat_intel.enrichments"}
_LIMIT_RE = re.compile(r'\bLIMIT\s+(\d+)\b', re.IGNORECASE)
_MAX_ROWS = 100


@tool
def query_clickhouse_raw(sql: str) -> str:
    """Execute a raw ClickHouse SQL query against First Light log storage.

    Use this when no pre-built tool covers the specific investigation needed.
    Useful for: finding all logs from a specific IP, tracing an event across
    sources, correlating timestamps, or running custom aggregations.

    Allowed tables: signoz_logs.logs_v2, threat_intel.enrichments
    Maximum 100 rows returned to protect context window.

    IMPORTANT — correct ClickHouse column names for signoz_logs.logs_v2:
      - body                          log message text
      - timestamp                     nanosecond unix timestamp
      - attributes_string['key']      string attributes (ssh.event, hostname, etc.)
      - attributes_number['key']      numeric attributes
      - resources_string['key']       resource labels (host.name, service.name, etc.)
      Do NOT use bare `attributes['key']` — it does not exist and will error.

    PERFORMANCE — queries run against 18M+ rows. To avoid timeouts:
      - ALWAYS filter by timestamp: timestamp >= now() - INTERVAL 24 HOUR * 1000000000
        (timestamp is nanoseconds — multiply seconds by 1000000000)
        Correct form: timestamp >= toUnixTimestamp(now() - INTERVAL 24 HOUR) * 1000000000
      - PREFER attributes_string/resources_string filters over body LIKE '%..%'
        (LIKE '%x%' is a full-table scan — use it only with a tight time filter)
      - Filter on resources_string['service.name'] first to narrow to one log source
      - Queries are hard-killed after 15 seconds — keep them focused

    Args:
        sql: ClickHouse SQL query. Must query an allowed table.

    Returns:
        JSON array of result rows, or an error message.
    """
    from agent.tools.logs import _execute_clickhouse_query

    # Validate table access — extract actual FROM/JOIN targets, not substring match
    _TABLE_RE = re.compile(r'\bFROM\s+([\w.]+)|\bJOIN\s+([\w.]+)', re.IGNORECASE)
    referenced = {(m.group(1) or m.group(2)).upper() for m in _TABLE_RE.finditer(sql)}
    allowed_upper = {t.upper() for t in _ALLOWED_TABLES}
    if not referenced or not referenced.issubset(allowed_upper):
        allowed = ", ".join(_ALLOWED_TABLES)
        return json.dumps({"error": f"Query must only target: {allowed}"})

    # Strip any existing LIMIT clauses and always append our own — more reliable
    # than regex substitution which can be defeated by subqueries or comments.
    # Also pass max_result_rows as a server-side hard cap.
    sql = _LIMIT_RE.sub("", sql).rstrip(";").rstrip() + f" LIMIT {_MAX_ROWS}"

    try:
        result = _execute_clickhouse_query(
            sql, ch_settings={
                "max_result_rows": _MAX_ROWS,
                "max_execution_time": 15,  # hard-kill on ClickHouse side after 15s
                "timeout_before_checking_execution_speed": 1,
            }
        )
        return result
    except Exception as e:
        logger.error("query_clickhouse_raw failed: %s", e)
        return json.dumps({"error": str(e)})
