#!/bin/bash
# Validate and deploy SSH/sudo parser to OTel collector

set -e

echo "========================================"
echo "SSH/sudo Parser Deployment Script"
echo "========================================"
echo

# Check if running on remote server or local
if [ "$(hostname)" != "docker.mcducklabs.com" ]; then
    echo "⚠️  This script should be run on docker.mcducklabs.com"
    echo "   Run: ssh tbailey@docker.mcducklabs.com 'bash -s' < $0"
    exit 1
fi

cd /opt/first-light

echo "Step 1: Pull latest changes from git"
git fetch origin
git pull origin main
echo "✓ Git pull complete"
echo

echo "Step 2: Validate OTel collector config syntax"
# Check if config is valid YAML
if docker run --rm -v "$(pwd)/signoz/otel-collector-config.yaml:/config.yaml" \
    otel/opentelemetry-collector-contrib:latest \
    validate --config /config.yaml > /dev/null 2>&1; then
    echo "✓ Config syntax is valid"
else
    echo "❌ Config validation failed!"
    echo "   Running validation with output:"
    docker run --rm -v "$(pwd)/signoz/otel-collector-config.yaml:/config.yaml" \
        otel/opentelemetry-collector-contrib:latest \
        validate --config /config.yaml
    exit 1
fi
echo

echo "Step 3: Backup current collector container"
BACKUP_NAME="signoz-otel-collector-backup-$(date +%Y%m%d-%H%M%S)"
if docker ps -a | grep -q signoz-otel-collector; then
    docker commit signoz-otel-collector "$BACKUP_NAME" > /dev/null
    echo "✓ Created backup: $BACKUP_NAME"
else
    echo "⚠️  Collector container not found, skipping backup"
fi
echo

echo "Step 4: Restart OTel collector with new config"
docker compose restart signoz-otel-collector
echo "✓ Collector restarted"
echo

echo "Step 5: Wait for collector to start (10 seconds)"
sleep 10
echo

echo "Step 6: Check collector health"
if docker compose ps signoz-otel-collector | grep -q "Up"; then
    echo "✓ Collector is running"
else
    echo "❌ Collector failed to start!"
    echo "   Checking logs:"
    docker compose logs --tail=50 signoz-otel-collector
    exit 1
fi
echo

echo "Step 7: Check for parser errors in logs"
if docker compose logs --tail=100 signoz-otel-collector | grep -i "error.*ssh\|error.*sudo"; then
    echo "⚠️  Found errors related to SSH/sudo parser in logs"
    echo "   Review above output"
else
    echo "✓ No parser errors found in logs"
fi
echo

echo "========================================"
echo "Deployment Complete!"
echo "========================================"
echo
echo "Next steps:"
echo "1. Monitor logs: docker compose logs -f signoz-otel-collector"
echo "2. Wait 5-10 minutes for SSH/sudo logs to be parsed"
echo "3. Query ClickHouse to verify parsed fields:"
echo "   docker exec signoz-clickhouse clickhouse-client --query \\"
echo "     \"SELECT body, mapKeys(attributes_string) FROM signoz_logs.logs_v2 \\"
echo "      WHERE body LIKE '%sshd%' LIMIT 5 FORMAT Vertical\\"
echo
echo "4. Check for parsed attributes:"
echo "   - ssh.event, ssh.user, ssh.source_ip, ssh.port"
echo "   - sudo.event, sudo.user, sudo.command, sudo.target_user"
echo
