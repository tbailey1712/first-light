# QNAP API Exporter

Prometheus exporter for QNAP NAS that collects detailed metrics via the QNAP API.

## Features

**Disk Metrics:**
- SMART status per disk
- Disk temperatures
- Bad sector counts
- Disk capacity

**Volume/Pool Metrics:**
- Per-volume usage (bytes)
- Pool capacity and free space
- Individual share sizes

**RAID Metrics:**
- RAID array status
- Degraded state detection
- Rebuild progress (if available)

**Container Station:**
- Container status (running/stopped)
- Per-container CPU usage
- Per-container memory usage
- Container image info

**Network Metrics:**
- Interface RX/TX bytes
- Connection counts
- Bandwidth statistics

**System Metrics:**
- Detailed uptime
- Service status
- Resource usage

## Setup

### 1. Create QNAP Monitoring User

In QNAP web UI:
1. **Control Panel** → **Privilege** → **Users**
2. Create user: `firstlight` / `f1rstl1ght`
3. Add to **Administrators** group (required for API access)
4. Deny all shared folder permissions
5. Disable unnecessary app permissions

### 2. Deploy Exporter

```bash
cd /opt/first-light/exporters/qnap-api
docker compose up -d --build
```

### 3. Verify

```bash
# Check logs
docker logs fl-qnap-api-exporter

# Test metrics endpoint
curl http://localhost:9004/metrics
```

## Metrics Format

```prometheus
# Disk metrics
qnap_disk_smart_status{disk="HDD1",host="nas.mcducklabs.com",model="WD Red"} 1
qnap_disk_temperature_celsius{disk="HDD1",host="nas.mcducklabs.com",model="WD Red"} 45
qnap_disk_bad_sectors{disk="HDD1",host="nas.mcducklabs.com"} 0

# Volume metrics
qnap_volume_capacity_bytes{host="nas.mcducklabs.com",pool="Pool1",volume="Backups"} 1e+13
qnap_volume_used_bytes{host="nas.mcducklabs.com",pool="Pool1",volume="Backups"} 5e+12
qnap_volume_free_bytes{host="nas.mcducklabs.com",pool="Pool1",volume="Backups"} 5e+12

# Container metrics
qnap_container_status{container="plex",host="nas.mcducklabs.com",image="plexinc/pms-docker"} 1
qnap_container_cpu_percent{container="plex",host="nas.mcducklabs.com"} 15.5
qnap_container_memory_bytes{container="plex",host="nas.mcducklabs.com"} 2.147483648e+09

# RAID metrics
qnap_raid_status{host="nas.mcducklabs.com",raid_id="1",type="raid5"} 1
```

## Integration with OTel Collector

Add to OTel collector scrape config:

```yaml
prometheus:
  config:
    scrape_configs:
      - job_name: qnap-api
        static_configs:
          - targets: ['fl-qnap-api-exporter:9004']
        scrape_interval: 60s
```

## Troubleshooting

**Authentication failed:**
- Verify user exists and has admin group membership
- Check password is correct
- User must be in Administrators group for API access

**Missing metrics:**
- Check QNAP firmware version (newer versions have more API endpoints)
- Some features require specific QNAP apps to be installed
- Container Station must be installed for container metrics

**Connection errors:**
- Verify HTTPS port (default 443)
- Check self-signed certificate is accepted
- Ensure NAS is reachable from docker network

## Configuration

Environment variables:
- `QNAP_HOST` - NAS hostname or IP (default: 192.168.2.9)
- `QNAP_USERNAME` - API username (default: firstlight)
- `QNAP_PASSWORD` - API password (default: f1rstl1ght)
- `QNAP_PORT` - HTTP/HTTPS port (default: 8080)
- `QNAP_PROTOCOL` - Protocol (default: http)
- `EXPORTER_PORT` - Metrics port (default: 9004)
- `SCRAPE_INTERVAL` - Collection interval in seconds (default: 60)

## API Endpoints Used

- `/cgi-bin/authLogin.cgi` - Authentication
- `/cgi-bin/management/manaRequest.cgi` - System info
- `/cgi-bin/disk/disk_manage.cgi` - Disk and volume info
- `/container-station/api/v1/container` - Container Station

