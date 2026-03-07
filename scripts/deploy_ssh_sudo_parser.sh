#!/bin/bash
# Simple deployment script for SSH/sudo parser
# Run this locally, it will SSH to the remote server and deploy

set -e

REMOTE_HOST="docker.mcducklabs.com"
REMOTE_USER="tbailey"
REMOTE_DIR="/opt/first-light"

echo "========================================"
echo "Deploying SSH/sudo Parser"
echo "========================================"
echo

echo "Connecting to $REMOTE_USER@$REMOTE_HOST..."
echo

ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" bash <<'ENDSSH'
set -e

cd /opt/first-light/signoz

echo "Step 1: Pull latest changes"
# Stash any local changes first
if git diff-files --quiet; then
    echo "  No local changes to stash"
else
    echo "  Stashing local changes..."
    git stash
fi
git pull origin main
echo "✓ Done"
echo

echo "Step 2: Validate config syntax"
# Basic YAML syntax check
if python3 -c "import yaml; yaml.safe_load(open('otel-collector-config.yaml'))" 2>/dev/null; then
    echo "✓ Config is valid YAML"
else
    echo "❌ Config has YAML syntax errors!"
    python3 -c "import yaml; yaml.safe_load(open('otel-collector-config.yaml'))"
    exit 1
fi
echo

echo "Step 3: Backup current state"
BACKUP_TIME=$(date +%Y%m%d-%H%M%S)
docker compose logs --tail=100 otel-collector > "/tmp/otel-collector-backup-${BACKUP_TIME}.log" || true
echo "✓ Logs backed up to /tmp/otel-collector-backup-${BACKUP_TIME}.log"
echo

echo "Step 4: Restart OTel collector"
docker compose restart otel-collector
echo "✓ Collector restarted"
echo

echo "Step 5: Wait for startup (15 seconds)"
sleep 15
echo

echo "Step 6: Check status"
if docker compose ps otel-collector | grep -q "Up"; then
    echo "✓ Collector is running"
else
    echo "❌ Collector is not running!"
    docker compose ps otel-collector
    exit 1
fi
echo

echo "Step 7: Check for errors in recent logs"
echo "Last 30 lines of logs:"
docker compose logs --tail=30 otel-collector
echo

echo "========================================"
echo "Deployment Complete!"
echo "========================================"
echo
echo "The SSH/sudo parser is now active."
echo
echo "To verify it's working:"
echo "1. Wait 5-10 minutes for SSH/sudo events"
echo "2. Query for parsed fields:"
echo "   docker exec signoz-clickhouse clickhouse-client --query \"SELECT body, mapKeys(attributes_string) FROM signoz_logs.logs_v2 WHERE body LIKE '%sshd%' OR body LIKE '%sudo%' LIMIT 5 FORMAT Vertical\""
echo
echo "Look for these attributes:"
echo "  - ssh.event, ssh.user, ssh.source_ip"
echo "  - sudo.event, sudo.user, sudo.command"
echo

ENDSSH

echo
echo "Deployment completed successfully!"
echo
