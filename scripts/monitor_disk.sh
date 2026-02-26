#!/bin/bash
# Disk space monitoring script for First Light
# Run via cron every 15 minutes to alert on high disk usage

THRESHOLD_WARN=75
THRESHOLD_CRIT=85
LOG_FILE="/var/log/first-light-disk-monitor.log"

# Get current disk usage percentage
USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')

echo "$(date): Disk usage at ${USAGE}%" >> "$LOG_FILE"

if [ "$USAGE" -ge "$THRESHOLD_CRIT" ]; then
    echo "$(date): CRITICAL - Disk usage at ${USAGE}%!" >> "$LOG_FILE"
    # Send critical alert
    curl -X POST http://localhost:3001/api/push \
        -H "Content-Type: application/json" \
        -d "{
            \"topic\": \"disk-alerts\",
            \"title\": \"🚨 CRITICAL: Disk ${USAGE}% Full\",
            \"message\": \"Disk usage is critically high. Clean up immediately!\",
            \"priority\": 5,
            \"tags\": [\"warning\",\"skull\"]
        }" 2>/dev/null
elif [ "$USAGE" -ge "$THRESHOLD_WARN" ]; then
    echo "$(date): WARNING - Disk usage at ${USAGE}%" >> "$LOG_FILE"
    # Send warning alert
    curl -X POST http://localhost:3001/api/push \
        -H "Content-Type: application/json" \
        -d "{
            \"topic\": \"disk-alerts\",
            \"title\": \"⚠️ WARNING: Disk ${USAGE}% Full\",
            \"message\": \"Disk usage is getting high. Consider cleanup.\",
            \"priority\": 3,
            \"tags\": [\"warning\"]
        }" 2>/dev/null
fi

# Check ClickHouse data sizes
CH_SIZE=$(sudo docker exec signoz-clickhouse clickhouse-client --query "
SELECT formatReadableSize(sum(bytes)) as size
FROM system.parts
WHERE active AND database IN ('signoz_logs', 'signoz_metrics', 'signoz_traces');
" 2>/dev/null | tr -d '\n')

echo "$(date): SigNoz data size: ${CH_SIZE}" >> "$LOG_FILE"
