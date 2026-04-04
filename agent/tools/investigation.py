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

    Args:
        sql: ClickHouse SQL query. Must query an allowed table.

    Returns:
        JSON array of result rows, or an error message.
    """
    from agent.tools.logs import _execute_clickhouse_query

    # Validate table access
    sql_upper = sql.upper()
    if not any(t.upper() in sql_upper for t in _ALLOWED_TABLES):
        allowed = ", ".join(_ALLOWED_TABLES)
        return json.dumps({"error": f"Query must target one of: {allowed}"})

    # Enforce row limit
    match = _LIMIT_RE.search(sql)
    if match:
        existing_limit = int(match.group(1))
        if existing_limit > _MAX_ROWS:
            sql = _LIMIT_RE.sub(f"LIMIT {_MAX_ROWS}", sql)
    else:
        sql = sql.rstrip(";").rstrip() + f" LIMIT {_MAX_ROWS}"

    try:
        result = _execute_clickhouse_query(sql)
        return result
    except Exception as e:
        logger.error("query_clickhouse_raw failed: %s", e)
        return json.dumps({"error": str(e)})
