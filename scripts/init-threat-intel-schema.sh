#!/bin/bash
# Initialize Threat Intelligence Schema in ClickHouse
#
# This script creates the threat_intel database and tables needed for
# storing IP enrichment data from threat intelligence sources.
#
# Usage:
#   ./scripts/init-threat-intel-schema.sh [clickhouse_host] [clickhouse_port]
#
# Defaults:
#   clickhouse_host: localhost (or signoz-clickhouse if running in Docker)
#   clickhouse_port: 9000

set -euo pipefail

CLICKHOUSE_HOST="${1:-localhost}"
CLICKHOUSE_PORT="${2:-9000}"

echo "=== Initializing Threat Intelligence Schema ==="
echo "ClickHouse Host: ${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"

# Create database
echo "Creating threat_intel database..."
docker exec -i signoz-clickhouse clickhouse-client --host "${CLICKHOUSE_HOST}" --port "${CLICKHOUSE_PORT}" <<'EOF'
CREATE DATABASE IF NOT EXISTS threat_intel;
EOF

echo "Database created successfully"

# Run migration
echo "Creating tables and views..."
docker exec -i signoz-clickhouse clickhouse-client --host "${CLICKHOUSE_HOST}" --port "${CLICKHOUSE_PORT}" --database threat_intel < clickhouse/migrations/001_threat_intel.sql

echo "Schema initialization complete!"

# Verify schema
echo ""
echo "=== Verifying Schema ==="
docker exec -i signoz-clickhouse clickhouse-client --host "${CLICKHOUSE_HOST}" --port "${CLICKHOUSE_PORT}" <<'EOF'
SHOW TABLES FROM threat_intel;
EOF

echo ""
echo "✓ Threat Intelligence schema is ready"
echo ""
echo "Next steps:"
echo "1. Add API keys to .env file (ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, ALIENVAULT_API_KEY)"
echo "2. Start the enrichment service: docker compose up -d threat-intel-enricher"
echo "3. Monitor metrics at http://localhost:9006/metrics"
