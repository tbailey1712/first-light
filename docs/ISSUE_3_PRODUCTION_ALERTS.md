# Issue #3: Production Alerts for SNMP Metrics

## Objective
Create meaningful, actionable alerts for network infrastructure monitoring.

## Available Metrics
- `interface_in_octets`, `interface_out_octets` - Traffic counters (use `rate()`)
- `interface_in_errors`, `interface_out_errors` - Error counters (use `rate()`)
- `interface_in_discards`, `interface_out_discards` - Discard counters, switch only (use `rate()`)
- `snmp_uptime` - Device uptime in hundredths of seconds

## Available Tags
- `device` - hostname (switch.mcducklabs.com, pfsense.mcducklabs.com, nas.mcducklabs.com, pve.mcducklabs.com)
- `device_type` - switch, firewall, nas, hypervisor
- `name` - interface name
- `instance` - IP address

## Priority Alerts

### 1. Interface Errors (CRITICAL)
**What it means**: Physical layer issues, bad cables, duplex mismatches, or hardware problems

**Alert Config:**
- **Name**: High Interface Errors
- **Metric**: `rate(interface_in_errors)` OR `rate(interface_out_errors)`
- **Condition**: `> 10` errors/sec for 5 minutes
- **Severity**: Warning
- **Notification**: Telegram
- **Message**:
  ```
  ⚠️ Interface Errors Detected
  Device: {{device}}
  Interface: {{name}}
  Error rate: {{value}} errors/sec

  Action: Check physical connection, cables, or port configuration
  ```

### 2. Interface Discards (WARNING)
**What it means**: Buffer overruns, congestion, switch queues full

**Alert Config:**
- **Name**: High Interface Discards
- **Metric**: `rate(interface_in_discards)` OR `rate(interface_out_discards)`
- **Condition**: `> 100` discards/sec for 5 minutes
- **Severity**: Warning
- **Notification**: Telegram
- **Message**:
  ```
  🟡 Interface Congestion
  Device: {{device}}
  Interface: {{name}}
  Discard rate: {{value}} packets/sec

  Action: Check for bandwidth saturation or QoS issues
  ```

### 3. Device Unreachable (CRITICAL)
**What it means**: SNMP polling failed, device down or network issue

**Alert Config:**
- **Name**: Device Unreachable
- **Metric**: `snmp_uptime`
- **Condition**: No data for 5 minutes
- **Severity**: Critical
- **Notification**: Telegram
- **Message**:
  ```
  🔴 Device Down
  Device: {{device}} ({{instance}})

  Last seen: {{last_timestamp}}
  Action: Check device status and network connectivity
  ```

### 4. Device Reboot Detected (INFO)
**What it means**: Device recently restarted (planned or unplanned)

**Alert Config:**
- **Name**: Device Reboot
- **Metric**: `snmp_uptime`
- **Condition**: `< 30000` (5 minutes in centiseconds)
- **Severity**: Info
- **Notification**: Telegram
- **Message**:
  ```
  🔵 Device Reboot Detected
  Device: {{device}}
  Uptime: {{value}} seconds

  Action: Verify this was planned maintenance
  ```

### 5. High Interface Utilization (WARNING)
**What it means**: Interface approaching capacity

**Alert Config:**
- **Name**: High Interface Traffic
- **Metric**: `rate(interface_in_octets)` OR `rate(interface_out_octets)`
- **Condition**: `> 100000000` (100 MB/sec) for 10 minutes
- **Severity**: Warning
- **Notification**: Telegram
- **Message**:
  ```
  🟡 High Interface Utilization
  Device: {{device}}
  Interface: {{name}}
  Traffic: {{value}} bytes/sec ({{value_mbps}} Mbps)

  Action: Monitor for sustained high usage
  ```

Note: Adjust threshold based on interface speed (1G vs 10G)

## Alert Routing Strategy

**Critical Alerts** (immediate action required):
- Device unreachable
- Interface errors > 100/sec
- Send immediately to Telegram

**Warning Alerts** (investigate soon):
- Interface errors 10-100/sec
- High discards
- High utilization
- Send to Telegram (can batch)

**Info Alerts** (informational):
- Device reboots
- Send to Telegram (batched/summary)

## Implementation Steps

For each alert:
1. Open SigNoz UI → Alerts → New Alert
2. Configure metric query with appropriate `rate()` or condition
3. Set threshold and duration
4. Set severity level
5. Select notification channel: "Telegram via webhook-relay"
6. Customize message template
7. Save and enable
8. Test by triggering condition (if possible)

## Testing Alerts

### Test Error Alert (if switch supports SNMP SET)
```bash
# Generate test traffic with errors (requires test equipment)
# OR wait for natural errors (not ideal)
```

### Test Reboot Alert
Restart a device or wait for the next planned maintenance.

### Test No-Data Alert
Temporarily block SNMP access:
```bash
# On switch, temporarily disable SNMP
# OR add firewall rule blocking UDP 161 from Telegraf
```

## Alert Tuning

After alerts run for 24-48 hours:
- Adjust thresholds if too noisy
- Add exclusions for known-good patterns
- Group related interfaces
- Consider rate-of-change alerts for anomaly detection

## Expected Alert Volume

**Normal operation:**
- 0-2 alerts/day (info level reboots)
- 0 critical alerts

**Degraded operation:**
- 5-10 warnings/day (transient issues)

**Incident:**
- Multiple critical alerts
- Sustained warning alerts

If alert volume is higher, tune thresholds or fix underlying issues.

## Next Steps After Alerts

- Issue #4: CrowdSec Security Monitoring
- Issue #5: Log Analysis (pfSense firewall logs)
- Issue #6: AI Agent for Anomaly Detection
