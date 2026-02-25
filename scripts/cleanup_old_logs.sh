#!/bin/bash
# Cleanup old logs from SigNoz ClickHouse
# This will delete logs older than specified days and reclaim disk space

set -e

LOGS_RETENTION_DAYS=${1:-30}
METRICS_RETENTION_DAYS=${2:-90}

echo "Setting up retention policies..."
echo "- Logs: ${LOGS_RETENTION_DAYS} days"
echo "- Metrics: ${METRICS_RETENTION_DAYS} days"
echo ""

# Set TTL on logs table
docker exec signoz-clickhouse clickhouse-client --query "
ALTER TABLE signoz_logs.logs
MODIFY TTL toDateTime(timestamp/1000000000) + INTERVAL ${LOGS_RETENTION_DAYS} DAY;
"

echo "✓ Logs TTL set to ${LOGS_RETENTION_DAYS} days"

# Set TTL on metrics
docker exec signoz-clickhouse clickhouse-client --query "
ALTER TABLE signoz_metrics.samples_v4
MODIFY TTL toDateTime(unix_milli/1000) + INTERVAL ${METRICS_RETENTION_DAYS} DAY;
"

echo "✓ Metrics TTL set to ${METRICS_RETENTION_DAYS} days"

# Set TTL on traces
docker exec signoz-clickhouse clickhouse-client --query "
ALTER TABLE signoz_traces.signoz_index_v2
MODIFY TTL timestamp + INTERVAL ${LOGS_RETENTION_DAYS} DAY;
"

echo "✓ Traces TTL set to ${LOGS_RETENTION_DAYS} days"

echo ""
echo "Checking current data sizes..."

docker exec signoz-clickhouse clickhouse-client --query "
SELECT
    table,
    formatReadableSize(sum(bytes)) as size,
    sum(rows) as rows
FROM system.parts
WHERE active AND database IN ('signoz_logs', 'signoz_metrics', 'signoz_traces')
GROUP BY table
ORDER BY sum(bytes) DESC;
"

echo ""
echo "Forcing cleanup of old data (this may take a while)..."

# Force merge to apply TTL immediately
docker exec signoz-clickhouse clickhouse-client --query "OPTIMIZE TABLE signoz_logs.logs FINAL;" &
docker exec signoz-clickhouse clickhouse-client --query "OPTIMIZE TABLE signoz_metrics.samples_v4 FINAL;" &
docker exec signoz-clickhouse clickhouse-client --query "OPTIMIZE TABLE signoz_traces.signoz_index_v2 FINAL;" &

wait

echo ""
echo "✓ Cleanup complete!"
echo ""
echo "New data sizes:"

docker exec signoz-clickhouse clickhouse-client --query "
SELECT
    table,
    formatReadableSize(sum(bytes)) as size,
    sum(rows) as rows
FROM system.parts
WHERE active AND database IN ('signoz_logs', 'signoz_metrics', 'signoz_traces')
GROUP BY table
ORDER BY sum(bytes) DESC;
"

echo ""
echo "Disk space:"
df -h | grep -E 'Filesystem|mapper'
