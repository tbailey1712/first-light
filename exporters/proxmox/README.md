# Proxmox VE Metrics Exporter

Prometheus exporter for Proxmox VE that collects VM, container, storage, and node metrics via the Proxmox API.

## Features

**VM Metrics:**
- CPU usage (ratio)
- Memory usage/total (bytes)
- Disk usage/total (bytes)
- Uptime (seconds)
- Status (running/stopped)

**Container (LXC) Metrics:**
- CPU usage (ratio)
- Memory usage/total (bytes)
- Disk usage/total (bytes)
- Uptime (seconds)
- Status (running/stopped)

**Storage Metrics:**
- Usage/total capacity (bytes)

**Node Metrics:**
- CPU usage (ratio)
- Memory usage/total (bytes)

## Setup

### 1. Create Proxmox API Token

In Proxmox web UI:
1. Go to **Datacenter** → **Permissions** → **API Tokens**
2. Click **Add**
3. Set:
   - User: Create a new user (e.g., `monitor@pve`)
   - Token ID: `metrics`
   - Privilege Separation: **Unchecked** (for simplicity)
4. Copy the Token Secret (UUID)

### 2. Set Permissions

Grant the user read-only permissions:
```bash
# On Proxmox host
pveum user add monitor@pve
pveum aclmod / -user monitor@pve -role PVEAuditor
```

### 3. Configure Environment

Add to `/opt/first-light/.env`:
```env
PROXMOX_HOST=pve.mcducklabs.com
PROXMOX_PORT=8006
PROXMOX_TOKEN_ID=monitor@pve!metrics
PROXMOX_TOKEN_SECRET=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
PROXMOX_NODE=pve
PROXMOX_VERIFY_SSL=false
```

### 4. Deploy

```bash
cd /opt/first-light/exporters/proxmox
docker compose up -d
```

### 5. Verify

```bash
# Check logs
docker logs fl-proxmox-exporter

# Test metrics endpoint
curl http://localhost:9002/metrics
```

## Metrics Format

```prometheus
# VM metrics
pve_vm_cpu_usage_ratio{vmid="100",name="homeassistant",node="pve"} 0.15
pve_vm_memory_usage_bytes{vmid="100",name="homeassistant",node="pve"} 4294967296
pve_vm_disk_usage_bytes{vmid="100",name="homeassistant",node="pve"} 10737418240

# Container metrics
pve_ct_cpu_usage_ratio{ctid="101",name="docker",node="pve"} 0.45
pve_ct_memory_usage_bytes{ctid="101",name="docker",node="pve"} 8589934592

# Storage metrics
pve_storage_usage_bytes{storage="local-lvm",node="pve"} 107374182400
pve_storage_total_bytes{storage="local-lvm",node="pve"} 536870912000

# Node metrics
pve_node_cpu_usage_ratio{node="pve"} 0.25
pve_node_memory_usage_bytes{node="pve"} 17179869184
```

## Integration with OTel Collector

The exporter runs on port `9002`. Add to OTel collector scrape config:

```yaml
prometheus:
  config:
    scrape_configs:
      - job_name: proxmox
        static_configs:
          - targets: ['fl-proxmox-exporter:9002']
        scrape_interval: 60s
```

## Troubleshooting

**Connection refused:**
- Check Proxmox is reachable: `curl -k https://pve.mcducklabs.com:8006`
- Verify firewall allows port 8006

**Authentication failed:**
- Verify token ID format: `username@realm!tokenid`
- Check token hasn't expired
- Ensure user has PVEAuditor role

**SSL errors:**
- Set `PROXMOX_VERIFY_SSL=false` for self-signed certs
- Or add CA certificate to container

**No metrics:**
- Check logs: `docker logs fl-proxmox-exporter`
- Verify API token permissions
- Test API manually: `curl -k -H "Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET" https://pve:8006/api2/json/cluster/resources`

## Configuration

Environment variables:
- `PROXMOX_HOST` - Proxmox server hostname/IP
- `PROXMOX_PORT` - API port (default: 8006)
- `PROXMOX_TOKEN_ID` - API token ID (format: user@realm!tokenid)
- `PROXMOX_TOKEN_SECRET` - API token secret/UUID
- `PROXMOX_NODE` - Node name (default: pve)
- `PROXMOX_VERIFY_SSL` - Verify SSL cert (default: false)
- `EXPORTER_PORT` - Metrics port (default: 9002)
- `SCRAPE_INTERVAL` - Collection interval in seconds (default: 60)
