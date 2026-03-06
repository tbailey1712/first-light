#!/bin/bash
# AdGuard Metrics Query Helper for ClickHouse
# Deploy to docker host at /opt/first-light/scripts/query_adguard_metrics.sh

set -euo pipefail

CLICKHOUSE="sudo docker exec signoz-clickhouse clickhouse-client -q"

case "${1:-help}" in
  top-clients)
    echo "Top 20 clients by query count (last 24h):"
    $CLICKHOUSE "
      SELECT
        simpleJSONExtractString(ts.labels, 'client.name') as client,
        simpleJSONExtractString(ts.labels, 'client.ip') as ip,
        sum(s.value) as total_queries
      FROM signoz_metrics.samples_v4 s
      JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
      WHERE s.metric_name = 'adguard.queries.total'
        AND s.unix_milli > toUnixTimestamp(now() - INTERVAL 24 HOUR) * 1000
      GROUP BY client, ip
      ORDER BY total_queries DESC
      LIMIT 20
    "
    ;;

  top-blocked)
    echo "Top 20 clients by blocks (last 24h):"
    $CLICKHOUSE "
      SELECT
        simpleJSONExtractString(ts.labels, 'client.name') as client,
        sum(s.value) as total_blocks
      FROM signoz_metrics.samples_v4 s
      JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
      WHERE s.metric_name = 'adguard.blocks.total'
        AND s.unix_milli > toUnixTimestamp(now() - INTERVAL 24 HOUR) * 1000
      GROUP BY client
      ORDER BY total_blocks DESC
      LIMIT 20
    "
    ;;

  block-rate)
    echo "Block rates by client (last 24h):"
    $CLICKHOUSE "
      SELECT
        simpleJSONExtractString(ts.labels, 'client.name') as client,
        round(avg(s.value), 2) as avg_block_rate
      FROM signoz_metrics.samples_v4 s
      JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
      WHERE s.metric_name = 'adguard.block.rate'
        AND s.unix_milli > toUnixTimestamp(now() - INTERVAL 24 HOUR) * 1000
      GROUP BY client
      ORDER BY avg_block_rate DESC
      LIMIT 20
    "
    ;;

  high-risk)
    echo "High-risk clients (risk score > 5):"
    $CLICKHOUSE "
      SELECT
        simpleJSONExtractString(ts.labels, 'client.name') as client,
        simpleJSONExtractString(ts.labels, 'client.ip') as ip,
        round(avg(s.value), 2) as risk_score
      FROM signoz_metrics.samples_v4 s
      JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
      WHERE s.metric_name = 'adguard.client.risk_score'
        AND s.unix_milli > toUnixTimestamp(now() - INTERVAL 24 HOUR) * 1000
      GROUP BY client, ip
      HAVING risk_score > 5
      ORDER BY risk_score DESC
    "
    ;;

  blocked-domains)
    echo "Top 20 blocked domains (last 24h):"
    $CLICKHOUSE "
      SELECT
        simpleJSONExtractString(ts.labels, 'domain') as domain,
        sum(s.value) as total_blocks
      FROM signoz_metrics.samples_v4 s
      JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
      WHERE s.metric_name = 'adguard.blocked_domains.total'
        AND s.unix_milli > toUnixTimestamp(now() - INTERVAL 24 HOUR) * 1000
      GROUP BY domain
      ORDER BY total_blocks DESC
      LIMIT 20
    "
    ;;

  traffic-type)
    echo "Query volume by traffic type (last 24h):"
    $CLICKHOUSE "
      SELECT
        simpleJSONExtractString(ts.labels, 'traffic.type') as traffic_type,
        sum(s.value) as total_queries,
        count(DISTINCT simpleJSONExtractString(ts.labels, 'client.ip')) as unique_clients
      FROM signoz_metrics.samples_v4 s
      JOIN signoz_metrics.time_series_v4 ts ON s.fingerprint = ts.fingerprint
      WHERE s.metric_name = 'adguard.queries.total'
        AND s.unix_milli > toUnixTimestamp(now() - INTERVAL 24 HOUR) * 1000
      GROUP BY traffic_type
      ORDER BY total_queries DESC
    "
    ;;

  help|*)
    cat << 'HELP'
AdGuard Metrics Query Helper

Usage: ./query_adguard_metrics.sh [command]

Commands:
  top-clients       Top 20 clients by query count
  top-blocked       Top 20 clients by blocked queries
  block-rate        Block rates by client
  high-risk         Clients with risk score > 5
  blocked-domains   Top 20 blocked domains
  traffic-type      Query volume by traffic type (user/automated)
  help              Show this help

Examples:
  ./query_adguard_metrics.sh top-clients
  ./query_adguard_metrics.sh high-risk
HELP
    ;;
esac
