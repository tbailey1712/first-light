-- Setup log retention for SigNoz ClickHouse
-- This will automatically delete logs older than the TTL period

-- Set 30-day TTL on logs table (adjust if needed)
ALTER TABLE signoz_logs.distributed_logs
ON CLUSTER cluster
MODIFY TTL toDateTime(timestamp/1000000000) + INTERVAL 30 DAY;

-- Set 30-day TTL on the local logs table
ALTER TABLE signoz_logs.logs
ON CLUSTER cluster
MODIFY TTL toDateTime(timestamp/1000000000) + INTERVAL 30 DAY;

-- Set 90-day TTL on metrics (metrics are smaller, can keep longer)
ALTER TABLE signoz_metrics.distributed_samples_v4
ON CLUSTER cluster
MODIFY TTL toDateTime(unix_milli/1000) + INTERVAL 90 DAY;

ALTER TABLE signoz_metrics.samples_v4
ON CLUSTER cluster
MODIFY TTL toDateTime(unix_milli/1000) + INTERVAL 90 DAY;

-- Set 30-day TTL on traces
ALTER TABLE signoz_traces.distributed_signoz_index_v2
ON CLUSTER cluster
MODIFY TTL timestamp + INTERVAL 30 DAY;

ALTER TABLE signoz_traces.signoz_index_v2
ON CLUSTER cluster
MODIFY TTL timestamp + INTERVAL 30 DAY;

-- Force immediate cleanup of old data
OPTIMIZE TABLE signoz_logs.logs FINAL;
OPTIMIZE TABLE signoz_metrics.samples_v4 FINAL;
OPTIMIZE TABLE signoz_traces.signoz_index_v2 FINAL;
