#!/bin/bash
# EMERGENCY: Delete all old logs and set aggressive retention
# This will keep only the last 7 days of logs

set -e

RETENTION_DAYS=${1:-7}

echo "⚠️  EMERGENCY CLEANUP - Keeping only last ${RETENTION_DAYS} days"
echo ""
df -h | grep -E 'Filesystem|mapper'
echo ""

# Calculate the cutoff timestamp (days ago in nanoseconds for logs)
CUTOFF_NANOS=$(date -d "${RETENTION_DAYS} days ago" +%s)000000000

echo "Deleting logs older than $(date -d "${RETENTION_DAYS} days ago")..."

# Delete old logs immediately
docker exec signoz-clickhouse clickhouse-client --query "
ALTER TABLE signoz_logs.logs
DELETE WHERE timestamp < ${CUTOFF_NANOS};
"

echo "Deleting old traces..."
docker exec signoz-clickhouse clickhouse-client --query "
ALTER TABLE signoz_traces.signoz_index_v2
DELETE WHERE timestamp < toDateTime(${CUTOFF_NANOS}/1000000000);
"

echo "Deleting old metrics (keeping 30 days)..."
CUTOFF_MILLIS=$(date -d "30 days ago" +%s)000
docker exec signoz-clickhouse clickhouse-client --query "
ALTER TABLE signoz_metrics.samples_v4
DELETE WHERE unix_milli < ${CUTOFF_MILLIS};
"

echo ""
echo "Setting TTL for automatic cleanup..."

# Set aggressive TTL
docker exec signoz-clickhouse clickhouse-client --query "
ALTER TABLE signoz_logs.logs
MODIFY TTL toDateTime(timestamp/1000000000) + INTERVAL ${RETENTION_DAYS} DAY;
"

docker exec signoz-clickhouse clickhouse-client --query "
ALTER TABLE signoz_traces.signoz_index_v2
MODIFY TTL timestamp + INTERVAL ${RETENTION_DAYS} DAY;
"

docker exec signoz-clickhouse clickhouse-client --query "
ALTER TABLE signoz_metrics.samples_v4
MODIFY TTL toDateTime(unix_milli/1000) + INTERVAL 30 DAY;
"

echo "✓ TTL set to ${RETENTION_DAYS} days for logs/traces"
echo ""
echo "Forcing cleanup (this will take a few minutes)..."

# Force merge to reclaim space
docker exec signoz-clickhouse clickhouse-client --query "OPTIMIZE TABLE signoz_logs.logs FINAL;" &
docker exec signoz-clickhouse clickhouse-client --query "OPTIMIZE TABLE signoz_traces.signoz_index_v2 FINAL;" &
docker exec signoz-clickhouse clickhouse-client --query "OPTIMIZE TABLE signoz_metrics.samples_v4 FINAL;" &

wait

echo ""
echo "✓ Cleanup complete!"
echo ""
echo "Final disk space:"
df -h | grep -E 'Filesystem|mapper'
