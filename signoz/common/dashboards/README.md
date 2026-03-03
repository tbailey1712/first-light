# Network Monitoring Dashboard for SigNoz

## Overview

This dashboard visualizes SNMP metrics collected from your network infrastructure:
- **Switch** (192.168.1.2) - switch.mcducklabs.com
- **pfSense Firewall** (192.168.1.1) - pfsense.mcducklabs.com
- **QNAP NAS** (192.168.2.9) - nas.mcducklabs.com
- **Proxmox Hypervisor** (192.168.1.89) - pve.mcducklabs.com

## Importing the Dashboard

### Option 1: Via SigNoz UI
1. Open SigNoz at `http://192.168.2.106:3000`
2. Navigate to **Dashboards** in the left sidebar
3. Click **"New Dashboard"** or **"Import"**
4. Copy and paste the contents of `network-monitoring.json`
5. Click **"Import"** or **"Save"**

### Option 2: Manual Panel Creation
If import doesn't work, create panels manually using the query examples below.

## Dashboard Panels

### 1. Total Network Traffic
- **Metrics**: `interface_in_octets` (rate), `interface_out_octets` (rate)
- **Shows**: Combined inbound/outbound traffic across all devices
- **Useful for**: Overall network load monitoring

### 2. Traffic by Device
- **Metrics**: Same as above, grouped by `device` tag
- **Shows**: Which devices are using the most bandwidth
- **Useful for**: Identifying bandwidth hogs

### 3. Switch - Top Interfaces
- **Metrics**: Interface octets filtered by `device=switch.mcducklabs.com`
- **Grouped by**: `name` (interface name)
- **Useful for**: Finding busy switch ports

### 4. pfSense - Interface Traffic
- **Metrics**: Interface octets filtered by `device=pfsense.mcducklabs.com`
- **Shows**: WAN/LAN/VLAN traffic on firewall
- **Useful for**: Internet bandwidth monitoring, VLAN traffic analysis

### 5. QNAP NAS - Interface Traffic
- **Shows**: NAS network activity
- **Useful for**: Backup/sync activity monitoring

### 6. Proxmox - Interface Traffic
- **Shows**: Hypervisor network activity
- **Useful for**: VM/container traffic patterns

### 7. Interface Errors
- **Metrics**: `interface_in_errors`, `interface_out_errors`
- **Shows**: Network errors by device and interface
- **⚠️ Alert on**: Any non-zero rate indicates network problems

### 8. Interface Discards (Switch)
- **Metrics**: `interface_in_discards`, `interface_out_discards`
- **Shows**: Packets dropped due to buffer/queue issues
- **⚠️ Alert on**: High discard rate = congestion

### 9. Device Uptime
- **Metric**: `snmp_uptime`
- **Shows**: How long each device has been running
- **Useful for**: Detecting reboots

### 10. Total Error Rate
- **Metric**: Sum of all interface errors
- **Shows**: Overall network health
- **⚠️ Alert on**: > 0 errors/sec

## Manual Query Examples

If you prefer to build panels manually in SigNoz:

### Total Inbound Traffic (bytes/sec)
```
Metric: interface_in_octets
Aggregation: rate
Group by: (none)
```

### Traffic per Device
```
Metric: interface_in_octets
Aggregation: rate
Group by: device
```

### pfSense WAN Interface Traffic
```
Metric: interface_in_octets
Aggregation: rate
Filters:
  - device = "pfsense.mcducklabs.com"
  - name = "igb0" (or your WAN interface name)
```

### Top 10 Busiest Interfaces
```
Metric: interface_in_octets
Aggregation: rate
Group by: device, name
Order by: Value (descending)
Limit: 10
```

### Interfaces with Errors
```
Metric: interface_in_errors
Aggregation: rate
Filter: value > 0
Group by: device, name
```

## Alerting Recommendations

Create alerts for:

1. **High Error Rate**
   - Metric: `interface_in_errors` OR `interface_out_errors`
   - Condition: `rate > 10/sec` for 5 minutes
   - Severity: Warning

2. **Interface Discards**
   - Metric: `interface_in_discards` OR `interface_out_discards`
   - Condition: `rate > 100/sec` for 5 minutes
   - Severity: Warning
   - Indicates: Network congestion

3. **Device Down**
   - Metric: `snmp_uptime`
   - Condition: No data for 5 minutes
   - Severity: Critical
   - Indicates: Device unreachable or SNMP failure

4. **Device Reboot**
   - Metric: `snmp_uptime`
   - Condition: `value < 300` (5 minutes in centiseconds)
   - Severity: Info
   - Indicates: Recent restart

## Available Metrics

All metrics collected by Telegraf:

- `interface_in_octets` - Bytes received (counter)
- `interface_out_octets` - Bytes sent (counter)
- `interface_in_errors` - Inbound errors (counter)
- `interface_out_errors` - Outbound errors (counter)
- `interface_in_discards` - Inbound discards (counter, switch only)
- `interface_out_discards` - Outbound discards (counter, switch only)
- `snmp_uptime` - Device uptime in hundredths of seconds

## Available Tags

Use these tags to filter and group metrics:

- `device` - Device hostname (e.g., "switch.mcducklabs.com")
- `device_type` - Device category ("switch", "firewall", "nas", "hypervisor")
- `instance` - Device IP address
- `name` - Interface name (e.g., "eth0", "igb0", "ge-0/0/1")
- `descr` - Interface description (switch only)
- `hostname` - SNMP sysName (device-reported hostname)
- `source` - Always "telegraf-snmp"
- `deployment.environment` - Always "production"

## Troubleshooting

### No data showing in panels
1. Check time range - set to "Last 1 hour"
2. Verify metric name is correct (check autocomplete)
3. Run ClickHouse query to confirm data exists:
   ```bash
   sudo docker exec signoz-clickhouse clickhouse-client --query \
     "SELECT DISTINCT metric_name FROM signoz_metrics.distributed_samples_v4 \
      WHERE metric_name LIKE 'interface_%' LIMIT 10"
   ```

### Metric not in autocomplete
- SigNoz caches metric names - may take a few minutes to appear
- Refresh the page
- Check ClickHouse directly (see above)

### Values seem wrong
- Remember: octets are **bytes**, not bits
- To convert to Mbps: `(rate * 8) / 1000000`
- Use `rate()` aggregation for counter metrics (octets, errors)
- Use `latest()` or `avg()` for gauge metrics (uptime)

## Next Steps

1. **Import this dashboard** into SigNoz
2. **Customize panel layouts** to your preference
3. **Create alerts** for errors and discards
4. **Add more metrics** - CPU, memory, disk if available via SNMP
5. **Set up notifications** to Telegram (webhook-relay is already configured)

## Data Collection Details

- **Collection interval**: 60 seconds
- **Devices monitored**: 4
- **Interfaces per device**: Varies (auto-discovered)
- **Metrics per minute**: ~65
- **Data retention**: Per SigNoz ClickHouse configuration
- **Collector**: Telegraf 1.32 (container: fl-telegraf-snmp)
