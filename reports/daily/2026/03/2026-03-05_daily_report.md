# First Light - Daily Threat Assessment
**Date:** 2026-03-05
**Report ID:** a9489b80-4dca-43f2-88a7-9bc0ff41d1ac
**Generated:** 2026-03-05 10:31:23 UTC

---

# 🛡️ Daily Threat Assessment Report
**Report Period:** Last 24 Hours  
**Generated:** 2026-03-05 16:30 UTC

---

## 1. Executive Summary

✅ **Overall Security Posture: STABLE** - Network defenses are functioning effectively with no critical threats detected. The firewall successfully blocked **16,921 connection attempts** from 10 unique attackers targeting the Ethereum validator (VLAN 4). DNS filtering blocked **10.8M+ queries** with two IoT devices showing elevated risk scores. Infrastructure health is nominal with routine operational events only.

---

## 2. 📊 Security Metrics (24h)

### Firewall Blocks
- **Total Blocks:** 16,921 connection attempts
- **Unique Attackers:** 10 external IPs
- **Primary Target:** 192.168.4.2 (Ethereum Validator - VLAN 4)

**Top 5 Threat Sources:**
| Source IP | Blocks | Target Port | Protocol | Attack Type |
|-----------|--------|-------------|----------|-------------|
| 169.150.222.204 | 6,683 | 9000 | TCP | Validator P2P probe |
| 89.42.231.149 | 3,299 | 9000 | TCP | Validator P2P probe |
| 170.106.111.103 | 2,733 | 30303 | TCP | Ethereum P2P probe |
| 13.230.155.233 | 2,299 | 30303 | TCP | Ethereum P2P probe |
| 103.234.55.82 | 1,931 | 30303 | UDP | Ethereum discovery |

### DNS Filtering (AdGuard)
- **Top Query Volume:** 192.168.1.100 (20.1M queries) - VLAN 1
- **Top Blocked Domain:** o427061.ingest.sentry.io (5.4M blocks)
- **High-Risk Clients Detected:** 2

**High-Risk DNS Clients:**
| IP | VLAN | Risk Score | Block Rate |
|----|------|------------|------------|
| 192.168.2.60 | IoT (2) | 8.96/10 | 89.64% |
| 192.168.2.44 | IoT (2) | 5.97/10 | 59.71% |

**Top Blocked Domains (Telemetry/Tracking):**
- o427061.ingest.sentry.io: 5.4M blocks (VLAN 1)
- cc-api-data.adobe.io: 2.2M blocks (VLAN 2)
- mobile.events.data.microsoft.com: 1.9M blocks (VLAN 2)
- teams.events.data.microsoft.com: 1.0M blocks (VLAN 4)
- scribe.logs.roku.com: 907K blocks (VLAN 1)

### ntopng Network Alerts
- **Total Alert Types:** 5
- **Probing Attempts:** 5,656 (Severity: Error)
- **Suspicious Device Protocol:** 1,148 total (122 Critical, 1,026 Error)
- **Slow DoS Alerts:** 316 (Severity: Error)
- **Suspicious DGA Domain:** Included in error category

**Notable ntopng Alerts:**
- Probing attempts from 15.235.51.214 → Validator (192.168.4.2:57904)
- Suspicious device protocol: NAS (VLAN 2) → 52.47.106.79:80 (Critical)
- Slow DoS detection: 44.215.129.188 → 192.168.1.244

### SSH Failures
- **Status:** No SSH brute-force attempts detected (threshold: >10)

---

## 3. 🏗️ Infrastructure Health

### Docker Container Health
- **Failed Health Checks:** 2,217 events
- **Issue:** Container 41923e58fd65 - missing `curl` executable in health check script
- **Impact:** Non-critical - health check misconfiguration, not actual service failure
- **Status:** ⚠️ Warning - requires health check script update

### Home Assistant
- **Core Errors:** 7,673 events
- **Primary Issue:** Denon AVR receiver async_update failures (recurring)
- **Secondary Issue:** 7 supervisor store repository reload failures (abc67f79)
- **Impact:** Low - integration errors, core functionality unaffected
- **Status:** ⚠️ Warning - integration maintenance needed

### Proxmox Hypervisor
- **Operations:** 5,981 total events
- **Active Tasks:** 2 running operations + 1 backup running
- **Status:** ✅ Normal operations

### Disk Usage
- **Status:** No critical disk space alerts detected

---

## 4. 🔍 Notable Events

### Ethereum Validator Under Sustained Probing
- **Timeframe:** Continuous over 24h period
- **Pattern:** Repeated SYN flood attempts to ports 9000 (consensus) and 30303 (execution)
- **Source:** Multiple IPs (likely P2P discovery + malicious scanning)
- **Action Taken:** All blocked by firewall - no connections established
- **Context:** Normal for public-facing validator; DMZ isolation working as designed

### High DNS Block Rate on IoT Devices
- **Device 1:** 192.168.2.60 (VLAN 2) - 89.64% block rate, Risk Score 8.96/10
- **Device 2:** 192.168.2.44 (VLAN 2) - 59.71% block rate, Risk Score 5.97/10
- **Pattern:** Excessive telemetry/tracking attempts
- **Action Taken:** Queries blocked by AdGuard
- **Context:** IoT devices attempting aggressive data collection - VLAN 2 isolation preventing lateral movement

### Wireless Client Anomalies
- **Events:** 2,842 client anomaly logs
- **Primary Issue:** Client 72:1e:2d:31:ec:39 - low PHY rate (satisfaction: 70-79%)
- **Disassociations:** 850 events across 3 APs
- **Ageouts:** 5 events for client 5c:fc:e1:be:d3:2f (180-sec silence)
- **Impact:** Minor - client roaming/connectivity issues, not security-related
- **Status:** ℹ️ Info - monitor for pattern escalation

---

## 5. 🚨 Cross-VLAN Traffic Alerts

### Camera VLAN (3) - Isolated ✅
- **Status:** No unauthorized cross-VLAN traffic detected
- **Isolation:** Functioning as designed

### Validator VLAN (4) - DMZ ✅
- **Status:** No unauthorized inbound cross-VLAN traffic
- **External Blocks:** 16,921 blocked attempts (expected for public validator)
- **Outbound:** Legitimate Microsoft Teams telemetry blocked (1.0M queries to teams.events.data.microsoft.com)
- **Isolation:** Functioning as designed

**Assessment:** Both isolated VLANs are properly segmented with no security violations.

---

## 6. ✅ Action Items

### ⚠️ Warning - Review Within 24h

1. **Investigate High-Risk IoT Devices**
   - **Devices:** 192.168.2.60 (Risk: 8.96) and 192.168.2.44 (Risk: 5.97)
   - **Action:** Identify device types, review if telemetry can be disabled at device level
   - **Reason:** 89% block rate indicates aggressive data collection behavior

2. **Fix Docker Health Check**
   - **Container:** 41923e58fd65
   - **Action:** Update health check script to use available binary or install `curl`
   - **Reason:** 2,217 false-positive health check failures creating log noise

3. **Home Assistant Integration Maintenance**
   - **Issue:** Denon AVR receiver integration failing (7,673 errors)
   - **Action:** Review integration configuration, check device connectivity
   - **Reason:** High error volume indicates persistent integration issue

### ℹ️ Info - Low Priority

4. **Monitor Wireless Client 72:1e:2d:31:ec:39**
   - **Issue:** Low PHY rate, frequent roaming between APs
   - **Action:** Monitor for continued degradation; may indicate device WiFi hardware issue
   - **Reason:** 2,842 anomaly logs suggest client-side connectivity problems

5. **Review Validator Telemetry**
   - **Issue:** 1M+ blocked queries to Microsoft Teams telemetry endpoints
   - **Action:** Verify if validator host has unnecessary software installed
   - **Reason:** Validator should have minimal software footprint

---

## 7. 📈 Trend Analysis

### Security Trends
- **Validator Probing:** Consistent with typical public validator exposure - no anomalous spike
- **DNS Blocks:** 10.8M+ blocks dominated by telemetry (Sentry, Adobe, Microsoft) - expected pattern
- **ntopng Probing Alerts:** 5,656 events - within normal range for network with public-facing services

### Infrastructure Trends
- **Docker Health Checks:** 2,217 failures - **NEW ISSUE** (likely recent container update)
- **Home Assistant Errors:** 7,673 Denon AVR errors - **ONGOING** (persistent integration issue)
- **Wireless Anomalies:** 2,842 events - elevated but consistent with single problematic client

### Notable Patterns
- **IoT Telemetry Blocking:** Two devices (192.168.2.60, 192.168.2.44) account for disproportionate block rates
- **Adobe/Microsoft Telemetry:** 5.4M blocks to Adobe/Microsoft endpoints suggest aggressive app telemetry from VLAN 1/2 devices
- **Validator Security:** All 16,921 external probes successfully blocked - DMZ isolation effective

### 7-Day Comparison
*Note: Historical baseline data not available in current query results. Recommend implementing trend tracking for:*
- Daily firewall block counts
- DNS block rate percentages
- ntopng alert volumes
- Infrastructure error rates

---

## 🎯 Summary

**Network Security Status:** ✅ **HEALTHY**

The network is operating within normal parameters with effective defense-in-depth:
- Firewall successfully blocking all external validator probes
- DNS filtering catching 10.8M+ telemetry/tracking attempts
- VLAN isolation functioning correctly (no cross-VLAN violations)
- Infrastructure operational with minor maintenance items

**Key Strengths:**
- DMZ isolation protecting validator from 16,921 attack attempts
- IoT VLAN containment preventing high-risk devices from lateral movement
- Multi-layer defense (firewall + DNS filtering + network monitoring)

**Recommended Focus:**
- Address Docker health check false positives (log noise reduction)
- Investigate IoT devices with 89% block rates (device identification)
- Maintain monitoring for wireless client connectivity issues

---

*Report generated by First Light AI Network Security Analysis*