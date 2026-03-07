# Infrastructure Log Parsing Audit

**Date:** March 7, 2026
**Purpose:** Audit structured field extraction from all infrastructure log sources

## Executive Summary

**Key Finding:** Only **pfSense filterlog** has comprehensive structured field parsing. All other systems send raw text logs with minimal to no field extraction.

### Parsing Status Overview

| System | Logs Collected? | Structured Parsing? | Status |
|--------|----------------|---------------------|---------|
| **pfSense (filterlog)** | ✅ Yes | ✅ **COMPLETE** | 8 fields extracted |
| **ntopng** | ✅ Yes | ❌ **NONE** | Raw text only |
| **UniFi APs (4x)** | ✅ Yes | ❌ **NONE** | Raw text only |
| **Home Assistant** | ✅ Yes | ❌ **NONE** | Raw text only |
| **AdGuard** | ✅ Yes | ❌ **NONE** | Raw text only |
| **Docker** | ✅ Yes | ❌ **NONE** | Raw text only |
| **Proxmox (pve)** | ✅ Yes | ❌ **NONE** | Raw text only |
| **NAS/QNAP** | ✅ Yes | ❌ **NONE** | Raw text only |
| **Switch** | ✅ Yes | ❌ **NONE** | Raw text only |
| **SSH/sudo events** | ✅ Yes | ⚠️ **DISABLED** | Parser exists but disabled |

## Detailed Analysis

### ✅ Fully Parsed Systems

#### pfSense Firewall (filterlog)

**Location:** `signoz/otel-collector-config.yaml` lines 109-131
**Processor:** `transform/pfsense`

**Extracted Fields:**
- `pfsense.interface` - Interface name (e.g., mvneta0.2)
- `pfsense.action` - Action taken (block/pass)
- `pfsense.direction` - Traffic direction (in/out)
- `pfsense.protocol` - Protocol (tcp/udp/icmp)
- `pfsense.src_ip` - Source IP address
- `pfsense.dst_ip` - Destination IP address
- `pfsense.src_port` - Source port (TCP/UDP only)
- `pfsense.dst_port` - Destination port (TCP/UDP only)
- `network.vlan` - VLAN tag (trusted/iot/guest) derived from interface
- `network.zone` - Network zone (edge)

**Sample Log Format:**
```
CSV format: rule,subrule,anchor,tracker,interface,reason,action,direction,ipver,...,proto_num,proto_name,length,src_ip,dst_ip,src_port,dst_port,...
```

**AI Agent Usage:** ✅ Agents can query blocked IPs, protocols, VLAN traffic patterns

---

### ❌ No Parsing (Raw Text Only)

#### ntopng

**Current Status:**
- Logs collected: ✅ Yes (~8,863 logs/24h)
- Parsing: ❌ None
- Filtering: ⚠️ Aggressive (only WARN+ severity, many alert types dropped)

**Sample Log Format:**
```
[Broadcast Domain Too Large][Warning] Threshold: 50 Host: 192.168.1.100
[DNS Data Exfiltration][Warning] Host: 192.168.2.52
[Too Many Flows][Info] Host: 192.168.1.5
```

**What Should Be Parsed:**
- `ntopng.alert_type` - Alert category (extracted from `[Alert Type]`)
- `ntopng.severity` - Severity level (extracted from `[Severity]`)
- `ntopng.host` - Affected host IP (extracted from `Host: X.X.X.X`)
- `ntopng.threshold` - Threshold value if present
- `ntopng.interface` - Network interface if present
- `ntopng.protocol` - Protocol if present

**Impact:** High priority - security alerts are not queryable by field

**Recommendation:** Create `transform/ntopng` processor similar to pfSense parser

---

#### UniFi Access Points (4 locations)

**Devices:**
- ap-first-floor.mcducklabs.com (~16,082 logs/24h)
- ap-second-floor.mcducklabs.com (~16,068 logs/24h)
- ap-basement.mcducklabs.com (~9,089 logs/24h)
- ap-wolcott.mcducklabs.com (~8,042 logs/24h)

**Current Status:**
- Logs collected: ✅ Yes (~49,281 logs/24h total)
- Parsing: ❌ None (raw text)
- Device tagging: ✅ Yes (device.type=access-point, network.zone=automation)

**Sample Log Format (typical):**
```
hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: authenticated
hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated
U7PG2,v4.3.20.11298,aa:bb:cc:dd:ee:ff,STA-DISCONNECTED,signal=-70
```

**What Should Be Parsed:**
- `unifi.event` - Event type (authenticated, associated, disconnected, roam)
- `unifi.interface` - Wireless interface (wlan0, wlan1)
- `unifi.client_mac` - Client MAC address
- `unifi.signal` - Signal strength (dBm)
- `unifi.ap_model` - AP model (U7PG2, U6LR, etc.)
- `unifi.firmware` - Firmware version
- `unifi.reason` - Disconnect reason if present

**Impact:** Medium priority - needed for wireless health monitoring

**Recommendation:** Create `transform/unifi` processor for common UniFi log patterns

---

#### Home Assistant

**Current Status:**
- Logs collected: ✅ Yes (~418,375 logs/24h - highest volume)
- Parsing: ❌ None (raw text)
- Device tagging: ✅ Yes (device.type=home-automation)

**Sample Log Format:**
```
2026-03-07 10:15:23 WARNING (MainThread) [homeassistant.components.sensor] Sensor binary_sensor.garage_door is unavailable
2026-03-07 10:16:45 ERROR (MainThread) [homeassistant.core] Error doing job: Task exception was never retrieved
```

**What Should Be Parsed:**
- `ha.timestamp` - Log timestamp
- `ha.level` - Log level (INFO, WARNING, ERROR, DEBUG)
- `ha.thread` - Thread name (MainThread, etc.)
- `ha.component` - HA component (homeassistant.components.sensor)
- `ha.entity_id` - Entity ID if present (binary_sensor.garage_door)
- `ha.message` - Clean message text

**Impact:** Medium priority - useful for infrastructure health monitoring

**Recommendation:** Create `transform/homeassistant` processor with regex parsing

---

#### AdGuard Home

**Current Status:**
- Logs collected: ✅ Yes
- Parsing: ❌ None (raw text)

**Sample Log Format:**
```
2026/03/07 10:15:23 192.168.1.100 ad.doubleclick.net BLOCKED
2026/03/07 10:16:45 192.168.2.52 www.google.com ALLOWED
```

**What Should Be Parsed:**
- `adguard.timestamp` - Query timestamp
- `adguard.client_ip` - Client IP
- `adguard.query_domain` - Queried domain
- `adguard.action` - Action (BLOCKED, ALLOWED)
- `adguard.query_type` - DNS query type (A, AAAA, PTR, etc.)

**Impact:** Low priority - metrics already available via AdGuard API/Prometheus exporter

**Note:** DNS query logs may be high volume. Consider sampling if full parsing is implemented.

---

#### Docker Containers

**Current Status:**
- Logs collected: ✅ Yes
- Parsing: ❌ None (raw text)

**Sample Log Format:**
```
[container-name] 2026-03-07T10:15:23.456Z INFO: Service started
```

**What Should Be Parsed:**
- `docker.container_name` - Container name
- `docker.container_id` - Container ID if present
- `docker.image` - Image name if present
- `docker.log_level` - Log level if parseable

**Impact:** Low priority - most docker logs are application-specific

**Recommendation:** Consider per-container parsing rules if specific containers need structured logs

---

#### Proxmox (pve)

**Current Status:**
- Logs collected: ✅ Yes
- Parsing: ❌ None (raw text)
- Device tagging: ✅ Yes (device.type=hypervisor, network.zone=compute)

**Sample Log Format:**
```
pvedaemon[12345]: VM 100 started
pvestatd[12346]: got timeout
```

**What Should Be Parsed:**
- `pve.daemon` - Proxmox daemon (pvedaemon, pvestatd, etc.)
- `pve.pid` - Process ID
- `pve.vm_id` - VM ID if present
- `pve.task` - Task type (started, stopped, migrated, etc.)
- `pve.event` - Event type

**Impact:** Low-Medium priority - useful for VM lifecycle tracking

---

#### NAS/QNAP

**Current Status:**
- Logs collected: ✅ Yes
- Parsing: ❌ None (raw text)
- Device tagging: ✅ Yes (device.type=nas, network.zone=storage)

**Sample Log Format:**
```
# Varies by QNAP model and log type
```

**What Should Be Parsed:**
- TBD - need sample logs to determine format

**Impact:** Low priority unless specific security/health events needed

---

#### Switch (SNMP-based)

**Current Status:**
- Logs collected: ✅ Yes (syslog)
- Parsing: ❌ None (raw text)
- Device tagging: ✅ Yes (device.type=switch, network.zone=core)

**Sample Log Format:**
```
# Varies by switch model
```

**What Should Be Parsed:**
- `switch.port` - Port number
- `switch.event` - Event type (link up/down, VLAN change, etc.)
- `switch.vlan` - VLAN ID if present

**Impact:** Low-Medium priority - useful for network topology changes

---

### ⚠️ Disabled Parsers

#### SSH/sudo Security Events

**Location:** `signoz/otel-collector-config.yaml` lines 131-138
**Processor:** `transform/ssh_sudo` - **DISABLED**

**Status:** Parser code exists but is commented out

**Reason:** Uses `replace_pattern` function which doesn't exist in OTTL (OpenTelemetry Transformation Language)

**What It Was Supposed To Parse:**
- SSH login attempts (successful/failed)
- sudo command executions
- Authentication failures
- Security-relevant auth events

**Impact:** High priority - security events are critical

**Recommendation:** Rewrite parser using correct OTTL functions (`replace_all_patterns` or regex extraction)

---

## Common Infrastructure (Already Parsed)

These are applied to ALL logs, not system-specific:

### Device Context Tagging

**Location:** `signoz/otel-collector-config.yaml` lines 86-107
**Processor:** `transform/device_context`

**Added Fields:**
- `device.type` - Device category (firewall, hypervisor, nas, switch, access-point, home-automation, server)
- `deployment.environment` - Always "production"
- `network.zone` - Network zone (edge, core, compute, storage, automation)

**Impact:** ✅ Enables filtering by device type and zone across all systems

---

## Recommendations by Priority

### 🔴 High Priority

1. **Re-enable SSH/sudo parser** - Security events are critical
   - Fix OTTL function usage
   - Extract: ssh.user, ssh.source_ip, ssh.event, sudo.user, sudo.command

2. **Add ntopng parsing** - Security alerts need structured queries
   - Extract: alert_type, severity, host, threshold, interface
   - Already identified as Task #24 (ntopng integration)

### 🟡 Medium Priority

3. **Add UniFi parsing** - Wireless health monitoring
   - Extract: event, client_mac, signal, interface, reason

4. **Add Home Assistant parsing** - Infrastructure health
   - Extract: level, component, entity_id, message

5. **Add Proxmox parsing** - VM lifecycle tracking
   - Extract: daemon, vm_id, task, event

### 🟢 Low Priority

6. **Add Switch parsing** - Network topology changes (if needed)
7. **Add Docker container parsing** - Per-container rules if needed
8. **Add AdGuard parsing** - Only if metrics/API insufficient
9. **Add NAS parsing** - Only if specific events needed

---

## Technical Implementation Notes

### OTTL (OpenTelemetry Transformation Language) Functions

**Available for parsing:**
- `Split(string, delimiter)` - Split CSV or delimited strings
- `IsMatch(string, regex)` - Test regex match
- `replace_all_patterns(...)` - Replace using regex (use this, NOT `replace_pattern`)
- `Substring(...)` - Extract substring
- `Concat(...)` - Concatenate strings
- `set(attribute, value)` - Set attribute value

**Pattern for adding new parser:**

```yaml
transform/system_name:
  error_mode: ignore
  log_statements:
    - context: log
      statements:
        # Only process specific logs
        - set(attributes["field"], value) where resource.attributes["service.name"] == "service-name"
        # Extract using regex or split
        - set(attributes["field"], Split(body, delimiter)[index]) where condition
        # Set additional fields
        ...
```

**Add to pipeline:**

```yaml
logs:
  receivers: [otlp, syslog]
  processors:
    - transform/syslog
    - filter/noise_reduction
    - transform/device_context
    - transform/pfsense
    - transform/system_name  # <-- Add new parser here
    - batch
  exporters: [clickhouselogsexporter, signozmeter]
```

---

## Impact on AI Agents

### Current Limitations

**With current parsing:**
- ✅ Can query pfSense blocks by IP, protocol, port, action
- ✅ Can filter by device type and network zone
- ❌ **Cannot query ntopng alerts by type or severity** (must search raw text)
- ❌ **Cannot query UniFi events by client or signal strength**
- ❌ **Cannot query HA errors by component**
- ❌ **Cannot query SSH/sudo security events at all**

### After Implementing Recommendations

**High priority changes enable:**
- ✅ Query security events: "Show all SSH login failures from external IPs"
- ✅ Query ntopng alerts: "Show all DNS Data Exfiltration alerts in last 24h"
- ✅ Query by structured fields instead of full-text search
- ✅ Build statistical models on parsed fields (e.g., alert frequency by type)
- ✅ Correlate events across systems using structured attributes

---

## Next Steps

1. **Immediate:** Fix SSH/sudo parser (Task #38)
2. **Phase 2:** Add ntopng parsing (Task #24)
3. **Phase 3:** Add UniFi + HA parsing
4. **Phase 4:** Evaluate need for remaining systems

**Before implementing each parser:**
- Query sample logs from ClickHouse to verify format
- Test parser with `otelcol validate` before deploying
- Verify fields appear in ClickHouse after deployment
- Update AI agent tools to leverage new structured fields

---

**Audit Completed:** March 7, 2026
**Next Review:** After implementing high-priority parsers
