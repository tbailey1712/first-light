# Missing Data Sources - First Light

## Status: February 26, 2026

During Phase 1.5 saved view testing, we discovered some expected devices are **not sending logs** to SigNoz.

---

## ✅ Devices Currently Logging

These devices are successfully sending logs to rsyslog → SigNoz:

- **docker** (`host.name = 'docker'`) - Docker host, observability stack
- **firewall.mcducklabs.com** (`host.name = 'firewall.mcducklabs.com'`) - pfSense firewall
- **pve** (`host.name = 'pve'`) - Proxmox hypervisor
- **UnifiSecondFloorBack** (`host.name = 'UnifiSecondFloorBack'`) - UniFi AP
- **UnifiFirstFloorFront** (`host.name = 'UnifiFirstFloorFront'`) - UniFi AP (assumed)
- **ntopng** (`host.name = 'ntopng'`) - Network monitoring

---

## ❌ Missing: QNAP NAS

**Host:** nas.mcducklabs.com (QNAP NAS)
**Status:** Not sending syslog to rsyslog container
**Impact:** No visibility into:
- Disk health/SMART data
- File access logs
- RAID status
- System warnings/errors

### How to Fix

**Option 1: Configure QNAP Syslog (Recommended)**

1. Log into QNAP web interface
2. Navigate to: **Control Panel → System → Logs**
3. Click **Remote Logging**
4. Enable remote logging
5. Configure:
   - **Server:** 192.168.2.106 (Docker host running rsyslog)
   - **Port:** 514
   - **Protocol:** UDP or TCP
6. Click **Apply**

**Option 2: Test with Manual Entry**

```bash
# From QNAP, test syslog connectivity
logger -n 192.168.2.106 -P 514 "Test message from QNAP"

# Check if it appears in SigNoz
# Filter: host.name = 'nas' OR host.name = 'nas.mcducklabs.com' OR body LIKE '%QNAP%'
```

### Expected Result

After configuration, QNAP logs should appear in SigNoz with:
- `host.name` = hostname configured on QNAP (likely "nas" or "nas.mcducklabs.com")
- `device.type` = "nas" (auto-tagged by OTel transform/device_context)

---

## ❌ Missing: AdGuard Home

**Host:** adguard (AdGuard Home DNS)
**Status:** Not sending syslog (or very low volume)
**Impact:** Limited visibility into:
- DNS queries
- Blocked domains
- Client query patterns

### Current Status

AdGuard was expected to send logs but not observed in recent 100 logs sample. Possible reasons:
1. Syslog not configured in AdGuard
2. Very low query volume (home network at night)
3. AdGuard only logs to its own web UI

### How to Fix

**Option 1: Enable AdGuard Syslog (if available)**

Check if AdGuard Home has syslog output option:
1. Open AdGuard web interface
2. Settings → General Settings
3. Look for "Logging" or "Syslog" options
4. Configure server: 192.168.2.106:514

**Option 2: Query AdGuard API Instead**

AdGuard has a REST API for query logs. Could create a separate exporter that:
- Polls AdGuard API periodically
- Converts query logs to OTLP format
- Sends to OTel collector

**Option 3: Accept Limited Visibility**

AdGuard web UI provides good built-in analytics. May not need full integration.

---

## 🟡 Partial: ntopng

**Status:** Sending logs BUT generating excessive noise
**Current State:** Aggressive filtering in place (drops 80-90% of logs)
**Issue:** Hostname sent as IP (192.168.1.5) instead of "ntopng"
**Workaround:** OTel transform processor maps IP → "ntopng"

### Potential Improvements

1. **Configure ntopng hostname properly** so it sends "ntopng" instead of IP
2. **Reduce alert generation** at ntopng source (disable certain alert categories)
3. **Selective interface monitoring** (disable lo, wlan0 if noisy)

---

## Summary

| Device | Status | Priority | Action Needed |
|--------|--------|----------|---------------|
| pfSense | ✅ Working | - | None |
| Proxmox | ✅ Working | - | None |
| Docker | ✅ Working | - | None |
| UniFi APs | ✅ Working | - | None |
| ntopng | 🟡 Partial | Medium | Reduce noise at source |
| **QNAP NAS** | ❌ Missing | **High** | **Configure syslog** |
| AdGuard | ❌ Missing | Low | Optional integration |

---

## Next Steps

1. **High Priority:** Configure QNAP syslog to enable NAS visibility
2. **Medium Priority:** Optimize ntopng alert generation
3. **Low Priority:** Evaluate AdGuard integration need

Once QNAP is configured, test the "Per-Device: QNAP NAS" saved view:
```
host.name = 'nas.mcducklabs.com' OR host.name = 'nas'
```
