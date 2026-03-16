# Device Inventory Discovery

Automatically discovers and tracks all network devices from multiple sources.

## Features

**Data Sources:**
- UniFi Controller API (wireless and wired clients)
- pfSense DHCP leases (planned)
- AdGuard Home DHCP (planned)
- Active network scanning (future)

**Device Tracking:**
- MAC address (primary key)
- IP address (current)
- Hostname
- Manufacturer (from MAC OUI)
- Device type classification
- VLAN/network location
- First seen / last seen timestamps
- Authorization status

**Device Classification:**
- Automatic classification based on manufacturer
- Hostname pattern matching
- Manual override support

**Prometheus Metrics:**
- Total device counts by type
- Active devices (seen in last 24h)
- New device discovery counter
- Unauthorized device alerts

## Setup

### 1. Configure Device Sources

Copy the example config and fill in your details:

```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your UniFi Controller details
```

**UniFi Controller:**
- Host: Your UniFi Controller IP or hostname
- Port: 8443 (default)
- Username/Password: Admin credentials
- Site: Usually "default"

### 2. Deploy

```bash
docker compose up -d --build
```

### 3. Verify

```bash
# Check logs
docker logs fl-device-inventory

# Test metrics endpoint
curl http://localhost:9005/metrics
```

## Metrics

```prometheus
# Total devices by type
network_devices_total{device_type="laptop",status="total"} 5
network_devices_total{device_type="phone",status="total"} 8
network_devices_total{device_type="iot",status="total"} 12

# Active devices (last 24h)
network_devices_total{device_type="all",status="active_24h"} 23

# Unauthorized devices
network_devices_total{device_type="all",status="unauthorized"} 1

# New device discoveries
network_devices_new_total 42
```

## Database Schema

SQLite database at `/data/device_inventory.db`:

```sql
CREATE TABLE devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    manufacturer TEXT,
    device_type TEXT,
    vlan TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    is_authorized BOOLEAN DEFAULT 1,
    notes TEXT
)
```

## Device Classification

### Automatic Rules

**By Manufacturer:**
- Apple → laptop/phone
- Samsung, Google → phone
- Amazon, Philips, Sonos → iot
- Ubiquiti, TP-Link → network

**By Hostname Pattern:**
- `pve*` → server
- `nas*`, `qnap*` → nas
- `switch*` → switch
- `ap*`, `unifi*` → access-point
- `iphone*`, `ipad*` → phone
- `macbook*` → laptop

### Manual Classification

Edit `config.yaml` to add custom rules:

```yaml
classification:
  manufacturer_rules:
    "MyIoTBrand": "iot"

  hostname_rules:
    "^cam-": "camera"
    "sensor-": "iot"
```

## Integration with SigNoz

Add to OTel collector scrape config:

```yaml
prometheus:
  config:
    scrape_configs:
      - job_name: device-inventory
        static_configs:
          - targets: ['fl-device-inventory:9005']
        scrape_interval: 60s
```

## Use Cases

**Security Monitoring:**
- Alert on new unknown devices
- Track unauthorized devices
- Monitor device movement between VLANs

**Network Documentation:**
- Automatic device inventory
- Track device lifecycle (first/last seen)
- Identify stale/abandoned devices

**Capacity Planning:**
- Device counts by type
- Growth trends over time
- VLAN utilization

## Querying the Database

```bash
# Access database directly
docker exec fl-device-inventory sqlite3 /data/device_inventory.db

# List all devices
SELECT mac, hostname, device_type, last_seen FROM devices ORDER BY last_seen DESC;

# Find devices not seen in 7 days
SELECT * FROM devices WHERE last_seen < datetime('now', '-7 days');

# Count devices by type
SELECT device_type, COUNT(*) FROM devices GROUP BY device_type;
```

## Configuration Reference

See `config.yaml.example` for full configuration options.

**Key Settings:**
- `discovery.interval`: Seconds between discovery runs (default: 300)
- `discovery.retain_days`: How long to keep historical data (default: 90)
- `metrics.port`: Prometheus metrics port (default: 9005)
- `alerts.new_device`: Enable new device alerts (default: true)

## Troubleshooting

**UniFi authentication fails:**
- Verify username/password are correct
- Check UniFi Controller is reachable
- Confirm SSL certificate settings (`verify_ssl`)
- Check logs: `docker logs fl-device-inventory`

**No devices discovered:**
- Verify UniFi Controller has active clients
- Check discovery interval isn't too long
- Review logs for API errors
- Ensure network connectivity from container

**Missing manufacturer names:**
- Some MACs don't have OUI registrations
- Will show as `null` in database
- Classification will rely on hostname patterns

## Future Enhancements

- pfSense DHCP lease integration
- AdGuard Home DHCP integration
- Active network scanning (nmap/arp)
- Device fingerprinting (OS detection)
- MAC vendor database updates
- Web UI for device management
- Export to CSV/JSON
- Integration with asset management systems
