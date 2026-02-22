# First Light - Portainer Deployment Guide

## Prerequisites
- Portainer installed and accessible
- Git repository accessible from Portainer host
- Port 514 (UDP/TCP) available on the host
- At least 4GB RAM available

## Deployment Method

Use Portainer **Stacks** with Git repository deployment.

### Stack Configuration

**Name:** `first-light`

**Repository URL:** (Your git repo URL)

**Repository Reference:** `main` (or your branch)

**Compose Path:** `docker-compose.yml`

**Environment Variables:**
```
CROWDSEC_ENROLLMENT_KEY=
VERSION=v0.112.0
OTELCOL_TAG=v0.142.0
```

### Important Notes

1. **Do NOT include `docker-compose.override.yml`** - That's for local Mac development only
2. **Port 514 requires host privileges** - Make sure Portainer agent has access
3. **Volumes will be created automatically** with the `fl-` prefix

## Post-Deployment

### 1. Verify Services

Check all containers are healthy:
- `fl-rsyslog` - Should be running
- `signoz-otel-collector` - Should be running
- `fl-crowdsec` - Should be running
- `signoz`, `signoz-clickhouse`, `signoz-zookeeper-1` - Should be running

### 2. Test Syslog Reception

Send a test message:
```bash
echo "<38>$(date '+%b %d %H:%M:%S') test-host app[123]: Test message" | nc -u <portainer-host-ip> 514
```

### 3. Verify Data Flow

**Check CrowdSec:**
```bash
docker exec fl-crowdsec cscli metrics show acquisition
```

**Check SigNoz:**
Open http://<portainer-host-ip>:8080 and navigate to Logs Explorer

### 4. Configure Network Devices

**pfSense:**
- Status → System Logs → Settings → Remote Logging
- Remote log servers: `<portainer-host-ip>:514`
- Everything: ✓

**Other devices:** Point syslog to `<portainer-host-ip>:514` (UDP or TCP)

## Troubleshooting

**No logs appearing?**
- Check rsyslog is receiving: `docker logs fl-rsyslog`
- Check file permissions: `docker exec fl-rsyslog ls -la /var/log/remote/`
- Check CrowdSec acquisition: `docker exec fl-crowdsec cscli metrics show acquisition`

**CrowdSec not parsing?**
- Check log format matches RFC3164
- Use: `docker exec fl-crowdsec cscli explain --file /var/log/remote/<hostname>/syslog.log --type syslog`

**SigNoz not showing logs?**
- Query ClickHouse directly: `docker exec signoz-clickhouse clickhouse-client --query "SELECT count() FROM signoz_logs.logs_v2"`
