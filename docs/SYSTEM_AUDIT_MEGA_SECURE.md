# First Light Network Observability Stack
## MEGA_SECURE System Security Audit
### Comprehensive Security & Architecture Review

**Date:** March 4, 2026
**Auditor:** Global Security Specialist (AI-Assisted)
**Scope:** Complete system-level security and architectural assessment
**Classification:** INTERNAL - Network Security Analysis

---

# Executive Summary

## Overall Security Rating: 7.5/10

**Status:** STRONG FOUNDATION with STRATEGIC GAPS

First Light has established a robust observability foundation with industry-standard tooling (SigNoz, CrowdSec, OpenTelemetry). The architecture demonstrates security-conscious design with VLAN segmentation, centralized logging, and threat intelligence integration. However, the system is currently in **detection-only mode** with minimal automated response capabilities and several data source gaps that create blind spots.

## Top 5 Strengths

1. **Comprehensive Log Collection Pipeline**: Multi-source aggregation (pfSense, Proxmox, UniFi, Docker) with structured parsing and noise filtering demonstrates professional-grade observability engineering.

2. **Defense-in-Depth Network Architecture**: Properly segmented VLANs with isolated camera network (VLAN 3) and DMZ for validator (VLAN 4) shows strong network security fundamentals.

3. **Threat Intelligence Integration**: CrowdSec with community parsers provides crowd-sourced threat detection beyond signature-based rules.

4. **Advanced Log Parsing**: OTel transform processors extract security-relevant attributes (pfSense filterlog CSV, ntopng alerts, UniFi events) enabling fast queries and correlation.

5. **Professional Observability Stack**: SigNoz Enterprise with ClickHouse backend provides scalable, queryable storage with 850k logs/day and 500k metrics/day throughput.

## Top 5 Critical Gaps

1. **NO AUTOMATED THREAT RESPONSE**: CrowdSec is detection-only; no bouncers configured. Blocked IPs are logged but not actively banned at pfSense/firewall level. Attackers can retry indefinitely.

2. **MAJOR DATA SOURCE GAPS**: AdGuard DNS (critical security data), ETH validator metrics (revenue-impacting), and pfSense API (no programmatic firewall control) are not integrated.

3. **NO ANOMALY DETECTION**: All alerting is rule-based. No statistical baseline modeling, no ML-based anomaly detection, no behavioral analytics. Cannot detect novel threats or zero-day patterns.

4. **LIMITED CROSS-VLAN TRAFFIC MONITORING**: While VLAN architecture is sound, there's no active monitoring for unexpected cross-VLAN traffic. The isolated Camera VLAN (VLAN 3) could be compromised without detection.

5. **AI AGENT NOT OPERATIONAL**: Agent framework exists but only has 5 AdGuard metric tools. No log querying, no security event analysis, no automated reporting. The "brain" of the system is not yet functional.

## Priority Recommendations

**Immediate (This Week):**
1. Enable CrowdSec bouncer on pfSense (auto-ban attackers)
2. Implement cross-VLAN traffic alerting (detect Camera VLAN breaches)
3. Create critical alert rules (disk space, validator offline, SSH brute force)

**Short-Term (1-2 Weeks):**
4. Integrate AdGuard API for DNS security analytics
5. Build comprehensive AI agent log query tools (SigNoz API)
6. Deploy automated daily threat assessment reports

**Medium-Term (1 Month):**
7. Implement statistical anomaly detection baselines
8. Add pfSense API integration for automated threat response
9. Create threat correlation engine (DNS + firewall + flow)

---

# 1. Security Posture Assessment

## 1.1 Current Security Monitoring Coverage

### ✅ Well-Monitored Areas

| Security Domain | Coverage | Data Sources | Rating |
|----------------|----------|--------------|--------|
| **Firewall Activity** | Excellent | pfSense filterlog with CSV parsing | 9/10 |
| **Infrastructure Logs** | Excellent | Proxmox, Docker, NAS, Home Assistant | 9/10 |
| **Wireless Security** | Good | UniFi AP logs with event extraction | 8/10 |
| **Network Flows** | Good | ntopng alerts (filtered for noise) | 7/10 |
| **SSH Attacks** | Good | Docker/pfSense syslog | 8/10 |
| **Container Health** | Good | Docker daemon logs | 7/10 |
| **SNMP Metrics** | Good | Switch, NAS, pfSense via Telegraf | 8/10 |
| **Threat Intelligence** | Good | CrowdSec community feeds | 7/10 |

**Overall Collection Quality:** 8.1/10 — Excellent breadth of data sources.

### ❌ Poorly Monitored Areas (Blind Spots)

| Security Domain | Coverage | Gap Impact | Risk Level |
|----------------|----------|------------|-----------|
| **DNS Security** | Poor | No DNS query visibility, malware C&C undetected | **CRITICAL** |
| **Validator Metrics** | None | Revenue loss from missed attestations invisible | **HIGH** |
| **Cross-VLAN Traffic** | None | Isolated VLANs could be breached undetected | **CRITICAL** |
| **API Access** | None | No logging of API calls to services | **MEDIUM** |
| **Data Exfiltration** | Poor | No file access logs, no outbound traffic baselines | **HIGH** |
| **Insider Threats** | None | No user behavior analytics | **LOW** |
| **Bluetooth/IoT** | None | IoT VLAN devices not individually monitored | **MEDIUM** |

**Critical Finding:** The AdGuard DNS gap is particularly severe. DNS is a common C&C channel for malware, and you have zero visibility into what domains your devices are querying beyond blocked counts.

## 1.2 Detection Capabilities Analysis

### Current Detection Methods

**1. Signature-Based Detection (High Confidence)**
- pfSense filterlog blocks (firewall rules)
- CrowdSec community scenarios (known attack patterns)
- ntopng security alerts (protocol violations, known threats)
- Log pattern matching (SSH failures, authentication errors)

**Effectiveness:** 8/10 for known threats
**Weakness:** Cannot detect novel attacks or zero-day exploits

**2. Rule-Based Alerting (Limited Deployment)**
- Currently: Only webhook-relay for SigNoz alerts (MVP)
- No critical alerts configured in audit review
- No automated escalation paths

**Effectiveness:** 2/10 (infrastructure exists, rules don't)
**Critical Gap:** You're collecting 850k logs/day but not actively alerting on threats.

**3. Threshold-Based Monitoring (Basic)**
- Disk space monitoring script (automated checks)
- SNMP interface error rates
- Container restart counts

**Effectiveness:** 5/10 (reactive, not predictive)

**4. Anomaly Detection (NOT DEPLOYED)**
- No statistical baselines
- No ML models
- No behavioral analytics

**Effectiveness:** 0/10
**Impact:** Cannot detect:
- Slow exfiltration attacks
- Insider threats
- Novel attack patterns
- Compromised IoT devices exhibiting unusual behavior

### Detection Capability Scoring

| Threat Type | Can Detect? | Confidence | MTTD* |
|------------|-------------|-----------|-------|
| Port scanning | ✅ YES | High | <1 min (pfSense) |
| SSH brute force | ✅ YES | High | <5 min (CrowdSec) |
| Known malware IPs | ✅ YES | High | <1 min (CrowdSec) |
| Cross-VLAN breach | ❌ NO | - | Never |
| DNS C&C traffic | ❌ NO | - | Never |
| Data exfiltration | ⚠️ MAYBE | Low | Hours-Days |
| Zero-day exploit | ❌ NO | - | Never |
| Compromised IoT device | ❌ NO | - | Never |
| Validator offline | ⚠️ PARTIAL | Medium | Manual check |
| Disk space exhaustion | ✅ YES | High | <15 min |

*MTTD = Mean Time To Detection

**Overall Detection Rating:** 5.5/10

## 1.3 Response Capabilities

### Current Response Mechanisms

**Automated (Active):**
- Disk space monitoring script (alerts only)
- Container auto-restart (Docker health checks)

**Manual (Passive):**
- CrowdSec decisions logged but not enforced (no bouncers)
- SigNoz alerts sent to Telegram but require human action
- No automated IP blocking
- No quarantine VLANs
- No automated incident playbooks

**Response Capability Rating:** 2/10

**Critical Finding:** This is a **detect-and-pray** security posture. You know when bad things happen but cannot automatically stop them.

### Response Time Analysis

| Incident Type | Current Response | Target Response | Gap |
|---------------|------------------|-----------------|-----|
| Persistent SSH attacker | Manual IP ban (24+ hours) | Auto-ban (5 min) | **23.9 hours** |
| Compromised IoT device | Manual investigation (days) | Auto-quarantine (10 min) | **Days** |
| Validator offline | Manual check (unknown) | Auto-alert (1 min) | **Unknown** |
| Disk space critical | Manual cleanup (hours) | Auto-purge old logs (5 min) | **Hours** |
| Firewall rule breach | Logged only | Block + alert (1 min) | **Never enforced** |

**Critical Gap:** Average response time is measured in **hours to days** when industry best practice for automated response is **minutes**.

## 1.4 Defense in Depth Analysis

### Network Layer (Strong)

```
              Internet
                 |
            [pfSense Plus]
                 |
         ┌───────┴───────┬───────────┬──────────┐
         |               |           |          |
    VLAN 1 (Trusted) VLAN 2 (IoT) VLAN 3   VLAN 4 (DMZ)
    Personal devices  Internet-OK (Cameras)  (Validator)
    Full access       Restricted  Isolated   Isolated
                                  NO Internet  DMZ rules
```

**Strengths:**
- Proper VLAN segmentation (Trusted/IoT/Isolated/DMZ)
- Camera VLAN fully isolated (best practice for surveillance)
- Validator in DMZ (best practice for high-value assets)
- pfSense Plus (commercial-grade firewall)

**Weaknesses:**
- No VLAN firewall rules audited in this review
- No documentation of allowed cross-VLAN flows
- Unclear if inter-VLAN routing is default-deny

**Rating:** 8/10 (strong architecture, rule validation needed)

### Application Layer (Moderate)

**Strengths:**
- Centralized logging (no local-only logs)
- Service account isolation (Docker containers)
- TLS/HTTPS for management interfaces
- SSH key authentication (public key noted in logs)

**Weaknesses:**
- No WAF (web application firewall)
- No API gateway with rate limiting
- Management interfaces exposed on standard ports
- No multi-factor authentication mentioned

**Rating:** 6/10

### Data Layer (Weak)

**Strengths:**
- Logs centralized in SigNoz (not on source devices)
- 90-day retention planned (per threat assessment doc)

**Weaknesses:**
- No encryption at rest mentioned
- No log integrity verification (hashing, signing)
- No backup validation process
- No disaster recovery plan
- Secrets in .env files (not secret manager)

**Rating:** 4/10

**Critical Finding:** An attacker with access to the Docker host could modify historical logs undetected. No log immutability controls.

## 1.5 Vulnerability Assessment

### Attack Surface Inventory

**Exposed Services (Internet-Facing):**
- pfSense WAN interface (firewall itself)
- Docker host SSH (port 22)
- Validator P2P ports (Ethereum consensus + execution)
- UniFi Controller (8443) - if port forwarded
- VPN endpoints - not documented

**Internal Services (Trust Boundary):**
- SigNoz UI (8081)
- Grafana (3000 or custom port)
- AdGuard (443)
- ntopng (443)
- Proxmox (8006)
- NAS web UI (unknown port)

**Management Access:**
- SSH to Docker host
- SSH to Proxmox
- Web UIs for all services
- SNMP v2c (switch, NAS) - weak authentication

### Vulnerability Classes

| Vulnerability Type | Severity | Exploitability | Current Controls |
|-------------------|----------|----------------|------------------|
| **No MFA on management interfaces** | HIGH | Easy | None |
| **SNMP v2c (community string)** | MEDIUM | Easy | None |
| **Docker host single point of failure** | CRITICAL | Easy (if compromised) | Container isolation |
| **No log integrity** | HIGH | Medium | None |
| **Secrets in .env files** | MEDIUM | Medium | File permissions only |
| **No network segmentation validation** | HIGH | Unknown | None |
| **CrowdSec detection-only** | CRITICAL | N/A | None (response gap) |
| **AdGuard API unauthenticated?** | HIGH | Unknown | Unknown |

### Most Likely Attack Vectors (Ranked)

1. **SSH Brute Force → Credential Compromise** (Likelihood: High, Impact: Critical)
   - Currently: Logged, CrowdSec detects, but not blocked
   - Mitigation: Enable CrowdSec bouncer + fail2ban

2. **Compromised IoT Device → Lateral Movement** (Likelihood: Medium, Impact: High)
   - Currently: No individual device monitoring, no anomaly detection
   - Mitigation: Per-device traffic baselines, DNS monitoring

3. **Validator Downtime → Revenue Loss** (Likelihood: Medium, Impact: High)
   - Currently: No monitoring, no alerting
   - Mitigation: Beacon API integration, attestation tracking

4. **Cross-VLAN Traffic → Isolated Network Breach** (Likelihood: Low, Impact: Critical)
   - Currently: Not monitored
   - Mitigation: Alert on ANY Camera VLAN outbound traffic

5. **Log Poisoning → Detection Evasion** (Likelihood: Low, Impact: High)
   - Currently: No log integrity checks
   - Mitigation: Log hashing, SIEM audit trails

**Overall Vulnerability Rating:** 6/10 (moderate risk, manageable with controls)

---

# 2. Architecture Review

## 2.1 Data Flow Security

### Current Data Flow

```
┌─────────────────┐
│  Data Sources   │
│ (pfSense, etc.) │
└────────┬────────┘
         │ UDP 514
         ↓
    ┌─────────┐
    │ rsyslog │ ←─ Single point of ingestion
    └─┬───┬───┘
      │   └──────────→ CrowdSec (file-based)
      │ TCP 5140
      ↓
  ┌──────────────┐
  │ OTel         │ ←─ Transformation layer
  │ Collector    │    (parsing, filtering)
  └──────┬───────┘
         │ OTLP
         ↓
    ┌──────────┐
    │ SigNoz   │
    │ ClickHouse│ ←─ Storage + Query
    └──────────┘
```

### Security Analysis

**Strengths:**
- Centralized ingestion point (rsyslog fan-out)
- Structured transformation (OTel processors)
- Immutable storage (ClickHouse - mostly)
- Fast query capability (columnar storage)

**Weaknesses:**
- **No encryption in transit** (syslog UDP 514 is plaintext)
- **No authentication** (any device can send to UDP 514)
- **No log integrity verification** (no hashing/signing)
- **Single point of failure** (rsyslog → OTel → ClickHouse)
- **No log forwarding** (no SIEM integration, no SOC)

**Critical Finding:** An attacker on the network could:
1. Inject false logs (UDP 514 spoofing)
2. Flood rsyslog (DoS the logging pipeline)
3. Sniff sensitive logs in transit (no TLS)

### Tamper-Proofing Assessment

| Component | Tamper Resistance | Risk |
|-----------|------------------|------|
| Source devices | Low (root access = arbitrary logs) | HIGH |
| rsyslog transit | None (plaintext UDP) | CRITICAL |
| OTel processing | Low (container compromise = log manipulation) | HIGH |
| ClickHouse storage | Medium (SQL access = deletion/modification) | MEDIUM |
| Backup logs | Unknown (no mention of backup integrity) | HIGH |

**Data Flow Security Rating:** 4/10

### Recommendations

1. **TLS-encrypted syslog** (rsyslog with TLS, client certificates)
2. **Log signing** (HMAC or digital signatures at source)
3. **Write-once storage** (separate immutable log tier)
4. **Separate monitoring stack** (watch the watchers)
5. **Offsite SIEM forwarding** (cloud SIEM like Splunk Cloud, Elastic Cloud)

## 2.2 Single Points of Failure

| Component | SPOF Risk | Failure Impact | Mitigation Status |
|-----------|-----------|----------------|-------------------|
| **Docker host** | CRITICAL | Total observability loss | ❌ None |
| rsyslog | HIGH | Log ingestion stops | ❌ None |
| OTel Collector | HIGH | Transformation/routing stops | ✅ Auto-restart |
| ClickHouse | CRITICAL | Query/storage unavailable | ❌ None |
| SigNoz UI | MEDIUM | No visualization | ✅ Auto-restart |
| pfSense | CRITICAL | Network down | ❓ Unknown (HA?) |
| Switch | HIGH | Network segmentation lost | ❌ None |

**Critical Finding:** The entire observability stack runs on a single Docker host. If that host fails:
- All logging stops
- All metrics stop
- All alerting stops
- Historical data inaccessible

### High Availability Architecture (Not Implemented)

```
Current (Single Host):
┌──────────────────────┐
│   Docker Host        │
│  - rsyslog           │
│  - OTel Collector    │
│  - ClickHouse        │
│  - SigNoz            │
│  - CrowdSec          │
└──────────────────────┘
     ↓ SPOF ↓

Recommended (HA):
┌─────────────┐  ┌─────────────┐
│  Docker 1   │  │  Docker 2   │
│  - rsyslog  │  │  - rsyslog  │  ← Load balanced
│  - OTel     │  │  - OTel     │
└──────┬──────┘  └──────┬──────┘
       └──────┬──────────┘
              ↓
      ┌──────────────┐
      │ ClickHouse   │
      │   Cluster    │  ← 3-node minimum
      └──────────────┘
```

**Recommendation:** For a homelab, HA is overkill. Instead:
1. **Scheduled backups** (ClickHouse snapshots to NAS)
2. **Fast recovery procedures** (docker-compose up on backup host)
3. **Local buffering** (rsyslog disk queue during downtime)

**SPOF Risk Rating:** 8/10 (acceptable for homelab, unacceptable for production)

## 2.3 Scalability Concerns

### Current Metrics (From CLAUDE.md)

- **Log Volume:** 850,000 logs/day (~10 logs/second)
- **Metric Volume:** 500,000 metrics/day (~6 metrics/second)
- **Retention:** ~7 days (per automated monitoring)
- **Storage Growth:** ~6 GB/day (per threat assessment plan)

### Capacity Projections

| Timeline | Log Volume | Storage | Bottleneck |
|----------|-----------|---------|------------|
| **Current** | 850k/day | ~30 GB (7d) | None |
| **+6 months** (add validator metrics) | 1.2M/day | ~50 GB (7d) | OTel CPU |
| **+1 year** (add all missing sources) | 2M/day | ~90 GB (7d) | ClickHouse disk I/O |
| **+2 years** (homelab growth) | 3M/day | ~150 GB (7d) | ClickHouse queries |

### Scalability Bottlenecks

1. **ClickHouse Disk I/O** (single disk, SSD required for >2M logs/day)
2. **OTel Transform Processor** (complex regex parsing, CPU-bound)
3. **rsyslog UDP Buffer** (limited buffer size, can drop logs under load)
4. **SigNoz UI Queries** (complex aggregations timeout on large datasets)

**Current Scalability Rating:** 7/10 (adequate for current load, plan needed for growth)

### Recommendations

1. **Storage Tiering:** Hot (7d SSD) → Warm (30d HDD) → Cold (90d object storage)
2. **Sampling:** High-volume sources (ntopng) use tail sampling (keep anomalies, sample normal)
3. **Pre-aggregation:** Roll up metrics to hourly/daily for long-term storage
4. **Query Optimization:** Materialized views for common security queries

## 2.4 Performance Optimization Opportunities

### Log Processing Pipeline

**Current Performance:**
- **Ingestion Latency:** <1 second (UDP → ClickHouse)
- **Query Latency:** 1-5 seconds (simple queries), 10-30 seconds (complex aggregations)
- **Transform CPU Usage:** Unknown (not monitored)

**Optimization Opportunities:**

1. **Remove Duplicate Parsing** (Current: regex runs multiple times)
   - Consolidate `transform/pfsense`, `transform/ntopng`, etc. into single pass
   - Estimated savings: 20-30% CPU

2. **Pre-filter Before Parsing** (Current: parse everything, then filter)
   - Move `filter/noise_reduction` BEFORE transform processors
   - Estimated savings: 40-50% CPU

3. **Compiled Regex** (Current: regex compiled on every log)
   - Pre-compile regex patterns in OTel config
   - Estimated savings: 10-15% CPU

4. **Batch Processing** (Current: batch 10k logs every 10s)
   - Increase batch size to 25k (trade latency for throughput)
   - Estimated savings: 15-20% CPU

**Estimated Total CPU Savings:** 50-70% with all optimizations

### Query Performance

**Slow Query Patterns (From Threat Assessment Plan):**

```sql
-- SLOW: Full table scan
SELECT COUNT(*) FROM signoz_logs
WHERE body LIKE '%failed%'

-- FAST: Indexed attribute filter
SELECT COUNT(*) FROM signoz_logs
WHERE attributes['security.event_type'] = 'ssh_auth'
```

**Optimization Recommendations:**

1. **Create Materialized Views** for common security queries
   - Daily firewall block counts by source IP
   - Hourly DNS block rates by client
   - Weekly threat intelligence summary

2. **Use Indexed Attributes** instead of `body LIKE`
   - Already doing this well (security.event_type, pfsense.action)

3. **Partition Strategy** (ClickHouse partitions by day currently)
   - Add secondary partitioning by `device.type` (firewall, nas, etc.)
   - Improves query pruning for device-specific queries

**Performance Optimization Rating:** 6/10 (good start, significant gains available)

## 2.5 Cost Optimization

### Current Infrastructure Costs

**Assumption:** Self-hosted on owned hardware (no cloud costs)

**Estimated Hardware Requirements:**
- Docker Host: 16-32 GB RAM, 500 GB SSD, 4-8 CPU cores
- Network: Prosumer switch, pfSense appliance
- Backup Storage: QNAP NAS

**Estimated Monthly Cost:** $0 operational (electricity ~$20/month)

### Cost-Benefit Analysis

| Component | Annual Cost | Value Delivered | ROI |
|-----------|-------------|-----------------|-----|
| **Observability Stack** | $0 (self-hosted) | Threat detection, compliance | ∞ |
| **Time Investment** | ~100 hours @ $50/hr = $5,000 | Full network visibility | 5-10x |
| **CrowdSec** | $0 (community) | Threat intelligence | ∞ |
| **AI Agent (planned)** | Anthropic API ~$20/month | Automated analysis | 50x |

**Cost Optimization Opportunities:**

1. **Reduce Log Volume** (current: 850k/day, many noisy logs)
   - Aggressive ntopng filtering already applied (good)
   - Consider sampling verbose debug logs (HA, Proxmox)
   - Estimated savings: 20-30% storage

2. **Optimize Retention** (current: 7 days, plan: 90 days)
   - Hot tier (7d): Full logs
   - Warm tier (30d): Aggregated metrics only
   - Cold tier (90d): Security events only
   - Estimated savings: 60-70% storage for 90d retention

3. **Open Source Alternatives** (current: SigNoz Enterprise)
   - Consideration: SigNoz Community Edition (if Enterprise features not needed)
   - Current cost: $0 (already using self-hosted)
   - Note: Enterprise features may be valuable (check license)

**Cost Optimization Rating:** 9/10 (already highly efficient, minimal cloud spend)

---

# 3. Data Collection Gaps

## 3.1 Critical Security Data NOT Collected

### Gap #1: DNS Query Logs (CRITICAL)

**Data Source:** AdGuard Home
**Current Status:** API available, hourly metrics exported, but NO raw query logs
**Impact:** Cannot detect:
- Malware C&C communication
- Data exfiltration via DNS tunneling
- Compromised devices querying suspicious domains
- DGA (Domain Generation Algorithm) patterns
- Timing analysis of DNS patterns

**Collection Method:**
- Option 1: AdGuard API `/control/querylog` (paginated, last 5k queries)
- Option 2: AdGuard syslog output (if available - check docs)
- Option 3: Scheduled API poller → SigNoz (every 5 minutes)

**Priority:** 🔴 CRITICAL — DNS is the #1 indicator of compromise

**Implementation Effort:** 4-6 hours (API integration + OTel exporter)

### Gap #2: Ethereum Validator Metrics (HIGH)

**Data Source:** Nimbus beacon API + Nethermind execution metrics
**Current Status:** Topology documented, metrics endpoints known, but NOT integrated
**Impact:** Cannot detect:
- Missed attestations (revenue loss ~$5-10/day if offline)
- Sync issues (validator ineffective)
- Peer count degradation (network isolation)
- Slashing events (catastrophic validator penalty)

**Collection Method:**
- Nimbus: Prometheus metrics on port 8008
- Nethermind: Prometheus metrics on port 6060
- Beacon API: `/eth/v1/validator/duties/attester/{epoch}`
- Integration: Telegraf scraper or direct OTel prometheus receiver

**Priority:** 🟠 HIGH — Direct financial impact

**Implementation Effort:** 3-4 hours (Prometheus scraper config)

### Gap #3: pfSense API Access (HIGH)

**Data Source:** pfSense Plus API
**Current Status:** Unknown if API is enabled, no integration
**Impact:** Cannot:
- Programmatically block IPs (automated response)
- Query firewall rules for audit
- Monitor firewall state changes
- Validate VLAN firewall rules
- Automate incident response

**Collection Method:**
- Enable API: System → Advanced → Enable REST API
- Create API key + secret
- Python client: `pfsense_client` library or httpx

**Priority:** 🟠 HIGH — Required for automated threat response

**Implementation Effort:** 2-3 hours (API setup + test script)

### Gap #4: Cross-VLAN Traffic Monitoring (CRITICAL)

**Data Source:** pfSense filterlog (already collected!)
**Current Status:** Logs collected, but NO alerting on cross-VLAN traffic
**Impact:** Cannot detect:
- Isolated Camera VLAN (VLAN 3) communicating outside NVR
- Validator DMZ (VLAN 4) unexpected connections
- IoT VLAN (VLAN 2) lateral movement

**Collection Method:**
- Already have the data: `attributes['network.vlan']` and `attributes['pfsense.action']`
- Need: SigNoz alert rule for Camera VLAN ANY outbound pass action
- Need: Baseline of "normal" cross-VLAN flows (validator → NTP, etc.)

**Priority:** 🔴 CRITICAL — Core security control

**Implementation Effort:** 1 hour (alert rule creation)

### Gap #5: Individual IoT Device Inventory (MEDIUM)

**Data Source:** UniFi Controller client list, DHCP leases, MAC addresses
**Current Status:** No device inventory, no per-device traffic baselines
**Impact:** Cannot:
- Identify rogue devices
- Detect compromised IoT device behavior changes
- Map device types to traffic patterns
- Alert on new devices appearing

**Collection Method:**
- UniFi API: `/api/s/{site}/stat/sta` (connected clients)
- pfSense DHCP leases API
- Create device inventory database (SQLite)
- Correlate MAC → IP → traffic patterns

**Priority:** 🟡 MEDIUM — Nice to have for advanced detection

**Implementation Effort:** 8-10 hours (device discovery + tracking system)

## 3.2 Blind Spots in Monitoring Coverage

### Visibility Matrix

| Asset | Logs | Metrics | API | Flows | Score |
|-------|------|---------|-----|-------|-------|
| pfSense | ✅ Full | ✅ SNMP | ❌ None | ✅ Firewall logs | 75% |
| Switch | ⚠️ Partial | ✅ SNMP | ❌ None | ❌ None | 50% |
| NAS | ✅ Full | ✅ SNMP | ❌ None | ❌ None | 50% |
| Proxmox | ✅ Full | ✅ SNMP | ❌ None | ❌ None | 50% |
| Docker Host | ✅ Full | ⚠️ Partial | ✅ Docker API | ❌ None | 75% |
| UniFi APs | ✅ Full | ⚠️ Partial | ❌ None | ❌ None | 50% |
| ntopng | ✅ Full | ❌ None | ❌ None | ✅ Flow analysis | 50% |
| AdGuard | ⚠️ Metrics only | ✅ Metrics | ❌ No logs | ❌ None | 25% |
| Validator | ❌ None | ❌ None | ❌ None | ❌ None | 0% |
| **Average** | | | | | **47%** |

### Geographical/Logical Blind Spots

```
Network Visibility Map:

┌─────────────────────────────────────────────────┐
│ pfSense (Edge)                    🟢 EXCELLENT  │
│ - All ingress/egress traffic                    │
│ - Firewall blocks                                │
│ - NAT translations                               │
└─────────────────────────────────────────────────┘
                     |
┌─────────────────────────────────────────────────┐
│ Switch (Core)                     🟡 GOOD       │
│ - Interface stats (SNMP)                         │
│ - Port errors/utilization                        │
│ ⚠️  NO: Port mirroring, per-device flows        │
└─────────────────────────────────────────────────┘
                     |
        ┌────────────┴────────────┐
        |                         |
┌───────────────┐        ┌────────────────┐
│ Trusted VLAN  │        │ IoT VLAN       │
│ 🟢 GOOD       │        │ 🟠 PARTIAL     │
│ - AP logs     │        │ - AP logs      │
│ - DNS queries │        │ ⚠️  NO: Device │
│ - Firewall    │        │     inventory  │
└───────────────┘        └────────────────┘

┌───────────────┐        ┌────────────────┐
│ Camera VLAN   │        │ Validator DMZ  │
│ 🔴 POOR       │        │ 🔴 CRITICAL    │
│ ⚠️  NO: Traffic│        │ ⚠️  NO: Metrics│
│     monitoring│        │ ⚠️  NO: Alerts │
│ ⚠️  NO: Alert │        │ ⚠️  NO: Balance│
│     on ANY    │        │     tracking   │
│     egress    │        │                │
└───────────────┘        └────────────────┘
```

### Time-Based Blind Spots

**Real-Time Monitoring:** Good (1-5 second latency)
**Historical Analysis:** Good (7-day retention, queryable)
**Trend Analysis:** Poor (no long-term aggregated metrics)
**Predictive:** None (no forecasting, no anomaly detection)

### Protocol-Specific Blind Spots

| Protocol/Layer | Visibility | Gap |
|---------------|-----------|-----|
| **DNS (UDP 53)** | ❌ Poor | No query logs (only block counts) |
| **HTTP/HTTPS** | ⚠️ Partial | Firewall logs only (no content inspection) |
| **SSH (TCP 22)** | ✅ Good | Full logs, brute force detection |
| **SMTP (TCP 25)** | ⚠️ Partial | Firewall blocks, no mail logs |
| **NTP (UDP 123)** | ❌ None | Not monitored |
| **mDNS (UDP 5353)** | ❌ None | IoT discovery not monitored |
| **SNMP (UDP 161)** | ⚠️ Partial | Metrics collected, no traps |
| **Blockchain P2P** | ❌ None | Validator peer traffic not analyzed |

## 3.3 Log Source Recommendations

### Immediate (Add This Week)

1. **AdGuard Query Logs** → SigNoz
   - Method: API poller every 5 minutes
   - Volume: ~50k queries/day (estimate)
   - Value: Critical for DNS-based threat detection

2. **Cross-VLAN Alert Rules** → Telegram
   - Method: SigNoz alert on Camera VLAN egress
   - Volume: 0 alerts expected (if configured correctly)
   - Value: Critical for VLAN isolation breach detection

3. **Validator Metrics** → SigNoz
   - Method: Telegraf Prometheus scraper
   - Volume: ~10k metrics/day
   - Value: High for financial monitoring

### Short-Term (Next 2 Weeks)

4. **pfSense API Integration** → First Light Agent
   - Method: Python API client
   - Value: Required for automated response

5. **Device Inventory Database** → SQLite
   - Method: UniFi + DHCP API polling
   - Value: Medium for IoT security

6. **Uptime Kuma Integration** → SigNoz
   - Method: API scraper or webhook
   - Value: Service availability monitoring

### Long-Term (Next Month)

7. **Port Mirroring → ntopng** (Hardware Upgrade)
   - Method: Configure switch SPAN port → ntopng
   - Value: Full packet capture for forensics

8. **Home Assistant Event Logs** → SigNoz
   - Already collected, need correlation with network events
   - Value: Physical + cyber event correlation

9. **Cloud Service Logs** (if any)
   - AWS CloudTrail, Google Cloud Logging, etc.
   - Value: Hybrid cloud visibility

## 3.4 Integration Opportunities

### Existing APIs Not Yet Leveraged

| Service | API Available | Current Use | Opportunity |
|---------|--------------|-------------|-------------|
| **AdGuard** | ✅ REST API | Hourly metrics | ❌ No query logs, no real-time |
| **Uptime Kuma** | ✅ REST API | None | ❌ Service status integration |
| **ntopng** | ✅ REST API | None | ⚠️ Flow data, top talkers |
| **Proxmox** | ✅ REST API | None | ⚠️ VM metrics, resource usage |
| **Home Assistant** | ✅ REST API + Websocket | None | ⚠️ Automation event correlation |
| **CrowdSec** | ✅ LAPI | None | ❌ Decision sync to pfSense |
| **Telegram** | ✅ Bot API | Alerts only | ⚠️ Interactive queries |

### Third-Party Threat Intelligence

**Currently Using:**
- CrowdSec community blocklists

**Could Add:**
- AbuseIPDB (check IP reputation)
- VirusTotal (check domains/IPs/hashes)
- AlienVault OTX (open threat exchange)
- Shodan (check if your IPs are exposed)
- Have I Been Pwned (credential leak monitoring)

**Implementation:**
- AI agent tools to query these APIs
- Enrich alerts with threat intelligence context
- Automated IP reputation scoring

### Webhook Integrations

**Currently Using:**
- SigNoz → Webhook Relay → Telegram

**Could Add:**
- CrowdSec → Webhook → Telegram (security alerts)
- AdGuard → Webhook → First Light agent (query patterns)
- Uptime Kuma → Webhook → Telegram (service down)
- GitHub Actions → Webhook → SigNoz (deployment events)

---

# 4. AI/ML Optimization Opportunities

## 4.1 Current AI/ML Capabilities

**Implemented:**
- LangGraph agent framework (basic)
- 5 AdGuard metric query tools
- System prompt with network topology
- ChatAnthropic LLM integration (Sonnet 4.5)

**NOT Implemented:**
- Log querying tools
- Security event analysis
- Anomaly detection
- Threat correlation
- Automated reporting
- Natural language alerting
- Predictive analytics

**AI Capability Rating:** 2/10 (infrastructure exists, functionality doesn't)

## 4.2 Where AI Can Add Maximum Value

### 1. Automated Threat Assessment Reports (Highest Priority)

**Current State:** None
**Opportunity:** Daily/weekly security digests (as designed in THREAT_ASSESSMENT_PLAN.md)

**Implementation:**
```python
# Daily morning report workflow
1. AI agent queries SigNoz for past 24h events
2. Analyzes patterns (firewall blocks, DNS blocks, SSH attempts)
3. Compares to 7-day baseline (statistical significance)
4. Generates narrative report with context
5. Sends to Telegram at 08:00 local time
```

**Value Add:**
- Saves 30-60 minutes of manual review daily
- Consistent security posture visibility
- Trend detection (spike in attacks, new threat patterns)
- Actionable recommendations ("Investigate IP 1.2.3.4")

**AI Techniques:**
- Structured data extraction (SigNoz queries)
- Statistical analysis (mean, stdev, Z-scores)
- Natural language generation (report writing)
- Rule-based alerting (threshold violations)

**Effort:** 12-16 hours (per THREAT_ASSESSMENT_PLAN.md Phase 1-2)

### 2. Anomaly Detection (High Priority)

**Current State:** None (all alerts are rule-based)
**Opportunity:** Detect novel threats without signatures

**Use Cases:**
- DNS query patterns deviate from baseline
- Network traffic volume spike (per-device)
- SSH login from new geography/time
- Service behavior change (CPU, memory, restarts)
- Cross-VLAN traffic that shouldn't exist

**Implementation Approaches:**

**Option A: Statistical Baselines (Simple, Fast)**
```python
# Example: DNS query volume anomaly
baseline = mean(last_7_days_queries_per_client)
stdev = stddev(last_7_days)
today_queries = get_today_queries_per_client()

for client in today_queries:
    z_score = (today - baseline[client]) / stdev[client]
    if z_score > 3:  # 3 standard deviations
        alert("Anomaly: Client {client} queries {z_score}x normal")
```

**Option B: ML Time-Series Models (Advanced)**
- ARIMA, LSTM, or Prophet for forecasting
- Train on historical metrics (past 90 days)
- Alert when actual diverges from predicted

**Value Add:**
- Detect zero-day attacks (no signature needed)
- Catch slow exfiltration (gradual traffic increase)
- Identify compromised IoT devices (behavior change)

**AI Techniques:**
- Time-series analysis
- Clustering (normal vs anomalous)
- Autoencoders (unsupervised learning)

**Effort:**
- Simple (statistical): 8-10 hours
- Advanced (ML): 40-60 hours

### 3. Threat Correlation Engine (High Priority)

**Current State:** Manual correlation (human analyst reviews logs)
**Opportunity:** Automatically connect related security events

**Correlation Patterns:**

```
Pattern 1: Multi-Stage Attack Detection
1. Port scan detected (pfSense blocks) from IP X
2. Same IP attempts SSH brute force (CrowdSec alert)
3. Same IP queries suspicious domain (AdGuard block)
→ AI Insight: "Coordinated attack from IP X, likely botnet"

Pattern 2: Compromised Device Detection
1. IoT device queries known malware domain (AdGuard)
2. Same device exhibits unusual traffic volume (ntopng)
3. Same device attempts cross-VLAN connection (pfSense)
→ AI Insight: "Device {name} likely compromised, quarantine recommended"

Pattern 3: Data Exfiltration
1. Gradual increase in outbound traffic (baseline deviation)
2. Traffic to unusual port (not 80/443/53)
3. Traffic to high-entropy domain (DGA detection)
→ AI Insight: "Possible data exfiltration from VLAN X to {domain}"
```

**Implementation:**
```python
class ThreatCorrelator:
    def __init__(self):
        self.event_buffer = []  # Sliding window (5 minutes)

    def add_event(self, event):
        self.event_buffer.append(event)
        self.check_patterns()

    def check_patterns(self):
        # Pattern: Same IP in firewall block + SSH failure + DNS block
        ips_in_firewall = {e.src_ip for e in events if e.type == 'firewall_block'}
        ips_in_ssh = {e.src_ip for e in events if e.type == 'ssh_failure'}
        ips_in_dns = {e.src_ip for e in events if e.type == 'dns_block'}

        coordinated = ips_in_firewall & ips_in_ssh & ips_in_dns
        if coordinated:
            alert(f"Coordinated attack from {coordinated}")
```

**Value Add:**
- Reduces alert fatigue (100 events → 3 correlated incidents)
- Tells a story ("This is what happened")
- Prioritizes threats (correlated = higher risk)

**AI Techniques:**
- Graph analysis (events as nodes, relationships as edges)
- Temporal reasoning (events within time window)
- Entity resolution (IP X = Client Y = Device Z)

**Effort:** 16-20 hours

### 4. Natural Language Query Interface (Medium Priority)

**Current State:** SQL queries to ClickHouse (technical users only)
**Opportunity:** Ask questions in plain English

**Examples:**
- "Show me all firewall blocks from Russia in the past week"
- "What's the top DNS query domain from IoT devices today?"
- "Has anyone tried to SSH into the validator?"
- "Compare this week's attack volume to last week"

**Implementation:**
```python
# Using LangChain SQL agent
from langchain.agents import create_sql_agent
from langchain_anthropic import ChatAnthropic

agent = create_sql_agent(
    llm=ChatAnthropic(model="claude-sonnet-4-5"),
    db=clickhouse_db,
    toolkit=sql_toolkit,
    agent_type="openai-tools"
)

response = agent.invoke("Show me top 10 blocked IPs this week")
# Agent generates SQL, executes, formats results
```

**Value Add:**
- Non-technical users can investigate
- Faster incident response (no SQL learning curve)
- Ad-hoc analysis without writing code

**AI Techniques:**
- Text-to-SQL (LLM translates English → SQL)
- Schema understanding (LLM knows table structure)
- Result summarization (LLM formats output)

**Effort:** 6-8 hours (LangChain SQL agent setup)

### 5. Predictive Analytics (Low Priority, Long-Term)

**Current State:** Reactive (alerts when bad things happen)
**Opportunity:** Predict problems before they occur

**Use Cases:**
- Disk space exhaustion forecast (currently: manual projection)
- Validator downtime prediction (peer count declining)
- Attack volume forecasting (security staffing)
- Service failure prediction (pattern before crash)

**Implementation:**
- Time-series forecasting (ARIMA, Prophet)
- Train on historical metrics (past 90 days)
- Daily forecast for next 7 days
- Alert if forecast crosses threshold

**Value Add:**
- Proactive maintenance (fix before breaking)
- Capacity planning (add disk before full)
- Security posture trending (improving or degrading?)

**AI Techniques:**
- Time-series forecasting
- Regression models
- Ensemble methods (multiple models)

**Effort:** 30-40 hours (research + implementation)

### 6. Autonomous Response Actions (Low Priority, Future)

**Current State:** Detection only (human decides action)
**Opportunity:** AI automatically remediates certain threats

**Safe Automation Candidates:**
- Block IP after 10 SSH failures (low risk)
- Quarantine IoT device to isolated VLAN (medium risk)
- Trigger snapshot before applying firewall rule (rollback)

**Dangerous Automation (NOT RECOMMENDED for homelab):**
- Auto-ban IPs (false positive = lost access)
- Auto-shutdown services (DoS yourself)
- Auto-delete files (data loss)

**Implementation:**
```python
# Example: CrowdSec decision → pfSense ban
def auto_ban_handler(event):
    if event.type == 'crowdsec_decision' and event.decision == 'ban':
        ip = event.ip
        # Safety checks
        if ip in WHITELIST:
            return
        if ip in local_network:
            alert("WARNING: Attempting to ban local IP {ip}")
            return

        # Execute ban
        pfsense_api.block_ip(ip, duration='24h')
        log(f"Auto-banned {ip} for 24h")
        notify_telegram(f"🚫 Auto-banned {ip}")
```

**Value Add:**
- Faster response (minutes vs hours)
- Consistent enforcement (no human error)
- Scales with attack volume (ban 100 IPs automatically)

**AI Techniques:**
- Rule-based automation (if-then logic)
- Confidence scoring (only act if >90% confidence)
- Audit trail (log all automated actions)

**Effort:** 12-16 hours + extensive testing

**Risk:** HIGH — automation can cause outages

## 4.3 AI/ML Roadmap

### Phase 1: Foundation (Current → 2 Weeks)

**Goal:** Functional AI agent with data access

**Deliverables:**
1. ✅ Agent framework (already done)
2. 🚧 SigNoz log query tools (8 tools minimum)
3. 🚧 Threat assessment report generator (daily reports)
4. 🚧 Basic statistical baseline tracking

**Key Tools to Build:**
```python
- query_firewall_blocks(hours, filters)
- query_ssh_failures(hours, source_ip)
- query_dns_blocks(hours, client, domain)
- query_cross_vlan_traffic(vlan_source, vlan_dest)
- query_ntopng_alerts(severity, hours)
- query_service_restarts(service_name, hours)
- query_disk_usage(host)
- query_interface_errors(interface, hours)
```

**Effort:** 16-20 hours

### Phase 2: Intelligence (Weeks 3-4)

**Goal:** Anomaly detection and correlation

**Deliverables:**
1. Statistical baseline models (7-day, 30-day)
2. Anomaly detection engine (Z-score based)
3. Threat correlation rules (10 patterns minimum)
4. Weekly rollup reports (trend analysis)

**Effort:** 20-25 hours

### Phase 3: Automation (Month 2)

**Goal:** Proactive security operations

**Deliverables:**
1. Automated threat response (CrowdSec → pfSense)
2. Natural language query interface
3. Predictive disk space alerts
4. Device inventory tracking

**Effort:** 30-35 hours

### Phase 4: Advanced ML (Month 3+)

**Goal:** ML-based threat detection

**Deliverables:**
1. LSTM time-series anomaly detection
2. DGA domain detection (machine learning)
3. Behavioral clustering (device fingerprinting)
4. Threat intelligence enrichment

**Effort:** 50-60 hours + ongoing tuning

---

# 5. Best Practices Compliance

## 5.1 Industry Standards Assessment

### NIST Cybersecurity Framework Mapping

| NIST Function | First Light Implementation | Score | Gaps |
|--------------|---------------------------|-------|------|
| **Identify** | Topology documented, asset inventory partial | 7/10 | No device inventory DB |
| **Protect** | VLAN segmentation, firewall, SSH keys | 8/10 | No MFA, weak SNMP |
| **Detect** | SigNoz + CrowdSec, 850k logs/day | 7/10 | No anomaly detection |
| **Respond** | Manual response, Telegram alerts | 3/10 | No automation, slow MTTR |
| **Recover** | Docker restart policies, manual restore | 4/10 | No backup validation |

**Overall NIST Score:** 5.8/10 (Moderate compliance)

### CIS Critical Security Controls

| CIS Control | Status | Implementation | Score |
|------------|--------|----------------|-------|
| 1. Inventory of Assets | ⚠️ Partial | Topology.yaml, no device DB | 5/10 |
| 2. Software Inventory | ❌ Missing | No software BOM tracking | 2/10 |
| 3. Data Protection | ⚠️ Partial | Logs centralized, no encryption | 5/10 |
| 4. Secure Configuration | ✅ Good | IaC (docker-compose), documented | 8/10 |
| 5. Account Management | ⚠️ Partial | SSH keys, no MFA | 6/10 |
| 6. Access Control | ✅ Good | VLANs, firewall rules | 8/10 |
| 7. Continuous Monitoring | ✅ Good | SigNoz, CrowdSec | 8/10 |
| 8. Audit Logs | ✅ Excellent | 850k logs/day, 90d retention | 9/10 |
| 9. Email/Web Protection | ⚠️ Partial | DNS filtering, no WAF | 5/10 |
| 10. Malware Defenses | ⚠️ Partial | CrowdSec, no endpoint AV | 5/10 |
| 11. Data Recovery | ⚠️ Partial | Restart policies, no backup test | 4/10 |
| 12. Network Defense | ✅ Good | Firewall, IDS (CrowdSec) | 8/10 |
| 13. Security Awareness | N/A | Homelab (single user) | N/A |
| 14. Service Provider Mgmt | N/A | No third-party providers | N/A |
| 15. Wireless Security | ✅ Good | WPA3 (assumed), client tracking | 7/10 |
| 16. Monitoring & Auditing | ✅ Excellent | Real-time + historical | 9/10 |
| 17. Security Program | ⚠️ Partial | Documented, no formal process | 6/10 |
| 18. Incident Response | ⚠️ Partial | Detection good, response weak | 5/10 |

**Overall CIS Score:** 6.1/10 (Above average for homelab)

### Homelab-Specific Best Practices

✅ **What First Light Does Right:**

1. **Documentation as Code** (CLAUDE.md, topology.yaml)
2. **Infrastructure as Code** (docker-compose.yml)
3. **Defense in Depth** (VLANs, firewall, CrowdSec, DNS filtering)
4. **Observability First** (logs before actions)
5. **Open Source** (SigNoz, CrowdSec, Telegraf — no vendor lock-in)
6. **Scalable Architecture** (can grow from homelab to small business)
7. **Security by Design** (isolated Camera VLAN, validator DMZ)

❌ **What's Missing (Homelab Context):**

1. **No Backup Validation** (backups may be corrupt, untested)
2. **Single Docker Host** (SPOF acceptable for homelab, but risky)
3. **Secrets in .env Files** (okay for homelab, not for production)
4. **No Disaster Recovery Plan** (how to rebuild from scratch?)
5. **No Penetration Testing** (internal red team exercise)

### Security Operations Best Practices

| Practice | Status | Notes |
|----------|--------|-------|
| **Centralized Logging** | ✅ Excellent | SigNoz with 7-day retention |
| **Log Immutability** | ❌ Missing | ClickHouse logs can be modified |
| **Security Monitoring** | ✅ Good | 24/7 collection (human review is manual) |
| **Incident Response Plan** | ⚠️ Partial | Threat assessment plan exists, no playbooks |
| **Threat Intelligence** | ✅ Good | CrowdSec community feeds |
| **Vulnerability Management** | ❌ Missing | No scanning (Nessus, OpenVAS) |
| **Patch Management** | ⚠️ Unknown | Container updates not documented |
| **Change Management** | ⚠️ Partial | Git for configs, no change log |
| **Asset Inventory** | ⚠️ Partial | Static topology, no dynamic discovery |
| **Network Segmentation** | ✅ Excellent | VLANs with proper isolation |

## 5.2 Observability Best Practices

### OpenTelemetry Standards Compliance

✅ **Correctly Implemented:**

1. **Semantic Conventions** (resource attributes like `host.name`, `service.name`)
2. **Structured Logging** (attributes not just in body)
3. **Batch Processing** (10k batch size, 10s timeout)
4. **Resource Detection** (system detector, env vars)
5. **Transformation Layer** (OTel processors, not downstream parsing)
6. **OTLP Protocol** (native OTLP to SigNoz)

⚠️ **Could Improve:**

1. **Span/Trace Context** (no distributed tracing for cross-service requests)
2. **Metric Labels** (SNMP metrics could have richer labels)
3. **Sampling** (no tail sampling for high-volume sources)
4. **Schema Registry** (no centralized attribute schema documentation)

**OTel Compliance Score:** 8/10 (Industry best practices)

### Logging Standards (Syslog RFC 5424)

Current: **RFC 3164** (legacy syslog)
Recommended: **RFC 5424** (structured syslog with key-value pairs)

**Upgrade Impact:**
- Structured data natively (no regex parsing)
- Better timezone handling (RFC 3164 has ambiguous timestamps)
- Message IDs (correlate related events)

**Effort:** Low (rsyslog config change)
**Priority:** Medium (current parsing works well enough)

### Security Information and Event Management (SIEM)

**SIEM Capabilities Present:**
- ✅ Log aggregation (rsyslog + SigNoz)
- ✅ Correlation (OTel transforms extract related fields)
- ✅ Alerting (SigNoz → Telegram)
- ✅ Dashboards (SigNoz UI)
- ⚠️ Threat intelligence (CrowdSec, could add more)
- ❌ Incident case management (no ticketing)
- ❌ Forensics tools (no PCAP analysis integration)

**First Light as SIEM:** 6/10 (Good foundation, missing advanced features)

## 5.3 What We're Doing Well ✅

### Strengths Summary

1. **Professional-Grade Architecture**
   - Industry-standard tooling (SigNoz, CrowdSec, OTel)
   - Scalable design (homelab → SMB ready)
   - Open source (no vendor lock-in)

2. **Comprehensive Data Collection**
   - 850k logs/day across 9+ sources
   - Structured parsing (CSV, regex, JSON)
   - Noise filtering (80-90% reduction on ntopng)

3. **Strong Network Security**
   - VLAN segmentation (Trusted/IoT/Isolated/DMZ)
   - Camera VLAN fully isolated (best practice)
   - Validator in DMZ (defense in depth)

4. **Documentation & Code Quality**
   - Infrastructure as Code (docker-compose)
   - Topology as Code (topology.yaml)
   - Comprehensive documentation (CLAUDE.md, threat plan)

5. **Threat Intelligence Integration**
   - CrowdSec with community scenarios
   - pfSense blocklists
   - AdGuard malware filtering

6. **Observability Excellence**
   - Fast queries (ClickHouse columnar storage)
   - 7-day retention with aggregation
   - Real-time dashboards (SigNoz UI)

## 5.4 What Needs Improvement ⚠️

### Medium-Priority Improvements

1. **Multi-Factor Authentication**
   - Add MFA to all management interfaces (AdGuard, Proxmox, pfSense)
   - Effort: 2-4 hours per service
   - Impact: Prevents credential compromise

2. **SNMP v3 Upgrade**
   - Switch and NAS use SNMP v2c (community string = weak auth)
   - Upgrade to SNMPv3 with user auth + encryption
   - Effort: 1-2 hours
   - Impact: Secures management plane

3. **Log Encryption in Transit**
   - Current: Plaintext syslog UDP 514
   - Target: TLS-encrypted syslog with client certificates
   - Effort: 4-6 hours (rsyslog-gnutls config)
   - Impact: Prevents log spoofing and sniffing

4. **Backup Validation Process**
   - Current: Unknown if backups exist or work
   - Target: Weekly automated restore test
   - Effort: 4-6 hours (script + monitoring)
   - Impact: Ensures disaster recovery readiness

5. **Change Management Log**
   - Current: Git for configs, but no unified change log
   - Target: Changelog with all infrastructure changes
   - Effort: 1 hour + discipline
   - Impact: Audit trail for troubleshooting

6. **Penetration Testing**
   - Current: No security testing
   - Target: Quarterly self-pentest (Nmap, Metasploit)
   - Effort: 4-8 hours per quarter
   - Impact: Find vulnerabilities before attackers do

7. **Service Dependency Mapping**
   - Current: docker-compose `depends_on` only
   - Target: Full dependency graph (what breaks if X fails)
   - Effort: 2-3 hours
   - Impact: Faster incident response

## 5.5 What's Missing ❌

### High-Impact Gaps

1. **Automated Threat Response** (Critical)
   - Current: Detection only
   - Gap: No auto-blocking, no quarantine
   - Fix: CrowdSec bouncer + pfSense API

2. **AdGuard DNS Logging** (Critical)
   - Current: No query logs
   - Gap: Cannot detect DNS-based threats
   - Fix: API integration (4-6 hours)

3. **Cross-VLAN Traffic Alerting** (Critical)
   - Current: Not monitored
   - Gap: Camera VLAN breach undetected
   - Fix: SigNoz alert rule (1 hour)

4. **Validator Monitoring** (High)
   - Current: No metrics
   - Gap: Revenue loss invisible
   - Fix: Prometheus scraper (3-4 hours)

5. **Anomaly Detection** (High)
   - Current: Rule-based only
   - Gap: Cannot detect novel threats
   - Fix: Statistical baselines (8-10 hours)

6. **AI Agent Operational** (High)
   - Current: Framework only
   - Gap: No automated reports, no log analysis
   - Fix: Build SigNoz query tools (16-20 hours)

7. **Log Integrity Verification** (Medium)
   - Current: No tamper detection
   - Gap: Logs could be modified
   - Fix: Log hashing + separate audit trail

8. **Device Inventory Database** (Medium)
   - Current: Static topology only
   - Gap: Rogue devices undetected
   - Fix: Dynamic discovery (8-10 hours)

---

# 6. Optimization Recommendations

## 6.1 Quick Wins (< 1 Day, High Impact)

### 1. Enable CrowdSec pfSense Bouncer (🔴 CRITICAL)

**Problem:** CrowdSec detects attackers but doesn't block them.
**Solution:** Install CrowdSec bouncer on pfSense to auto-ban IPs.

**Steps:**
1. SSH to pfSense
2. Install package: `pkg install crowdsec-firewall-bouncer`
3. Configure: `/usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`
   - API URL: `http://192.168.2.106:8080` (CrowdSec container)
   - API Key: Get from `docker exec fl-crowdsec cscli bouncers add pfsense-bouncer`
4. Test: `crowdsec-firewall-bouncer -c /path/to/config.yaml -v`
5. Enable systemd service

**Impact:**
- Reduces MTTB (Mean Time To Block) from 24+ hours to <5 minutes
- Stops persistent attackers automatically
- Reduces SSH brute force success rate to near zero

**Effort:** 1-2 hours
**Risk:** Low (can disable bouncer if false positives)

### 2. Create Cross-VLAN Traffic Alert (🔴 CRITICAL)

**Problem:** Camera VLAN (VLAN 3) could communicate outside without detection.
**Solution:** SigNoz alert rule for any Camera VLAN egress traffic.

**Steps:**
1. Open SigNoz UI → Alerts
2. Create new alert rule:
   ```
   Query: host_name = 'firewall.mcducklabs.com'
          AND network_vlan = 'cameras'
          AND pfsense_action = 'pass'
   Threshold: > 0 events in 5 minutes
   Severity: CRITICAL
   Notification: Telegram webhook
   ```
3. Test: Manually create pass rule on Camera VLAN, verify alert fires

**Impact:**
- Detects VLAN isolation breaches immediately
- Protects high-value surveillance footage
- Compliance with security policy

**Effort:** 30 minutes
**Risk:** None (alert only, no blocking)

### 3. Add Critical Disk Space Alert (🟠 HIGH)

**Problem:** Disk full = logging stops = security blind.
**Solution:** SigNoz alert on disk usage >85%.

**Steps:**
1. Verify disk metrics are collected (check SNMP or Docker host metrics)
2. Create alert:
   ```
   Query: disk_usage_percent{host="docker.mcducklabs.com"} > 85
   Threshold: Above 85% for 10 minutes
   Severity: CRITICAL
   Notification: Telegram
   ```
3. Test: Fill disk to 86% temporarily, verify alert

**Impact:**
- Prevents log pipeline failure
- Gives time for cleanup (85% = warning, 95% = critical)
- Automated monitoring (replaces manual checks)

**Effort:** 30 minutes
**Risk:** None

### 4. SSH Brute Force Alert (🟠 HIGH)

**Problem:** SSH attacks are logged but not alerted.
**Solution:** SigNoz alert on >10 SSH failures from same IP in 5 minutes.

**Steps:**
1. Create alert:
   ```
   Query: body LIKE '%sshd%Failed%'
   Group by: attributes['source_ip']
   Threshold: COUNT > 10 in 5 minutes
   Severity: WARNING
   Notification: Telegram
   ```
2. Test: Trigger 11 failed SSH attempts

**Impact:**
- Early warning of credential stuffing attack
- Allows manual IP ban before success
- Complements CrowdSec (which already detects this, but belt-and-suspenders)

**Effort:** 30 minutes
**Risk:** None

### 5. Validator Offline Alert (🟠 HIGH, if applicable)

**Problem:** Validator downtime = revenue loss (~$5-10/day).
**Solution:** Alert if no validator metrics received for 5 minutes.

**Steps:**
1. First, integrate validator metrics (see Short-Term #1 below)
2. Create no-data alert:
   ```
   Query: absence(nimbus_beacon_peers) for 5 minutes
   Severity: CRITICAL
   Notification: Telegram
   ```

**Impact:**
- Catches validator process crash immediately
- Minimizes attestation misses
- Financial protection

**Effort:** 30 minutes (after metrics integrated)
**Risk:** None

**Total Quick Wins Effort:** 3-4 hours
**Total Impact:** Transforms security posture from reactive to proactive

## 6.2 Short-Term (1-7 Days)

### 1. Integrate Ethereum Validator Metrics (🟠 HIGH)

**Deliverable:** Real-time validator monitoring in SigNoz

**Steps:**
1. Configure Telegraf to scrape Prometheus endpoints:
   ```toml
   [[inputs.prometheus]]
     urls = [
       "http://vldtr.mcducklabs.com:8008/metrics",  # Nimbus
       "http://vldtr.mcducklabs.com:6060/metrics"   # Nethermind
     ]
     metric_version = 2
   ```
2. Add to `telegraf-snmp` container or create new `telegraf-validator` service
3. Verify metrics in SigNoz: Search for `nimbus_` and `nethermind_` metrics
4. Create dashboard:
   - Attestation effectiveness
   - Peer counts (consensus + execution)
   - Sync status
   - Balance tracking (query beacon API)

**Key Metrics:**
- `beacon_attestations_success_total` (should increase constantly)
- `beacon_attestations_missed_total` (should stay at 0)
- `beacon_peers` (should be 50-100)
- `ethereum_peer_count` (execution layer peers)

**Effort:** 3-4 hours
**Value:** High (direct financial impact)

### 2. AdGuard DNS Query Log Integration (🔴 CRITICAL)

**Deliverable:** Full DNS query visibility in SigNoz

**Implementation Option A: API Poller (Recommended)**
```python
# adguard-query-exporter/exporter.py
import httpx
import time
from opentelemetry import logs

def poll_adguard_queries():
    response = httpx.get(
        "https://adguard.mcducklabs.com/control/querylog",
        params={"older_than": last_query_timestamp, "limit": 1000}
    )
    for query in response.json():
        log_record = {
            "timestamp": query["time"],
            "attributes": {
                "query.client": query["client"],
                "query.domain": query["question"]["name"],
                "query.type": query["question"]["type"],
                "query.blocked": query["filtered"],
                "query.reason": query["reason"]
            }
        }
        otel_logger.emit(log_record)

# Run every 5 minutes via cron
```

**Implementation Option B: Direct Syslog (if AdGuard supports)**
- Check AdGuard docs for syslog output option
- Configure to send to rsyslog:5514

**Effort:** 4-6 hours (Option A), 1 hour (Option B if available)
**Value:** Critical (enables DNS-based threat detection)

### 3. Build AI Agent Log Query Tools (🟠 HIGH)

**Deliverable:** 8+ LangChain tools for SigNoz querying

**Tools to Build:**
```python
@tool
def query_firewall_blocks(hours: int = 24, limit: int = 100) -> str:
    """Query pfSense firewall block events."""
    # Uses SigNoz API: host_name='firewall' AND pfsense_action='block'

@tool
def query_ssh_failures(hours: int = 24, source_ip: str = None) -> str:
    """Query SSH authentication failures."""
    # Uses SigNoz API: body LIKE '%sshd%Failed%'

@tool
def query_cross_vlan_traffic(vlan_source: str, hours: int = 24) -> str:
    """Query traffic from specified VLAN to other VLANs."""
    # Detects isolation breaches

# ... 5 more tools (see THREAT_ASSESSMENT_PLAN.md)
```

**Integration with Existing:**
- Add to `agent/tools/logs.py`
- Update `agent/graph.py` to include new tools
- Test with `test_agent.py`

**Effort:** 8-12 hours
**Value:** High (enables automated threat analysis)

### 4. Implement Daily Threat Assessment Report (🟠 HIGH)

**Deliverable:** Automated daily security digest emailed at 08:00

**Implementation:**
- Follow THREAT_ASSESSMENT_PLAN.md Phase 1 (MVP Daily Report)
- Query SigNoz for past 24h metrics
- Generate Markdown report
- Convert to HTML, send via Telegram (or email if configured)

**Report Includes:**
- Firewall block count (vs 7-day average)
- DNS block count (vs 7-day average)
- SSH brute force attempts
- Top 3 security events
- Disk space status
- Service health check

**Effort:** 6-8 hours (per threat assessment plan)
**Value:** High (daily security visibility)

### 5. pfSense API Integration (🟠 HIGH)

**Deliverable:** Programmatic firewall control from AI agent

**Steps:**
1. Enable pfSense REST API:
   - System → Advanced → Enable API
   - Create API key + secret
   - Store in `.env`: `PFSENSE_API_KEY`, `PFSENSE_API_SECRET`
2. Build Python client:
   ```python
   # agent/tools/pfsense.py
   @tool
   def block_ip_on_firewall(ip: str, duration: str = "24h") -> str:
       """Block an IP on pfSense firewall."""
       response = httpx.post(
           f"https://{PFSENSE_HOST}/api/v1/firewall/alias/entry",
           auth=(API_KEY, API_SECRET),
           json={"alias": "blocklist", "address": ip, "descr": f"Auto-blocked {duration}"}
       )
       return f"Blocked {ip} for {duration}"
   ```
3. Test manually before enabling automation

**Effort:** 2-3 hours
**Value:** High (required for automated threat response)

**Risk:** HIGH (automation can block legitimate IPs)
**Mitigation:** Whitelist trusted IPs, require manual approval for first 30 days

### 6. Create Baseline Metrics Database (🟡 MEDIUM)

**Deliverable:** SQLite database tracking 7-day and 30-day baselines

**Schema:**
```sql
CREATE TABLE baselines (
    metric_name TEXT,
    baseline_7d_mean REAL,
    baseline_7d_stdev REAL,
    baseline_30d_mean REAL,
    baseline_30d_stdev REAL,
    updated_at TIMESTAMP
);

-- Examples:
-- ('firewall_blocks_per_day', 1634, 287, 1589, 412, '2026-03-04')
-- ('dns_blocks_per_day', 223, 45, 218, 52, '2026-03-04')
```

**Update Process:**
- Daily cron job queries SigNoz for past 7d and 30d
- Calculates mean and standard deviation
- Updates baseline table
- Used by AI agent for anomaly detection

**Effort:** 4-5 hours
**Value:** Medium (enables statistical anomaly detection)

**Total Short-Term Effort:** 28-38 hours (1 full week)

## 6.3 Medium-Term (1-4 Weeks)

### 1. Statistical Anomaly Detection Engine (🟠 HIGH)

**Deliverable:** Automated anomaly alerts based on statistical baselines

**Implementation:**
```python
# agent/anomaly_detector.py
class AnomalyDetector:
    def check_anomaly(self, metric_name, current_value):
        baseline = get_baseline(metric_name)
        z_score = (current_value - baseline.mean) / baseline.stdev

        if abs(z_score) > 3:
            return {
                "anomaly": True,
                "severity": "high" if z_score > 4 else "medium",
                "message": f"{metric_name} is {z_score:.1f} standard deviations from normal"
            }
        return {"anomaly": False}

# Run every 15 minutes, check key metrics
metrics_to_monitor = [
    "firewall_blocks_per_hour",
    "dns_queries_per_client",
    "ssh_failures_per_hour",
    "network_bandwidth_mbps",
    "disk_growth_gb_per_day"
]
```

**Anomalies Detected:**
- Sudden spike in firewall blocks (DDoS or targeted attack)
- Client queries 10x normal (compromised device)
- SSH failures 5x normal (credential stuffing)
- Bandwidth spike (data exfiltration or streaming)
- Disk growth 3x normal (log flood attack)

**Effort:** 8-10 hours
**Value:** High (catches novel threats)

### 2. Threat Correlation Engine (🟠 HIGH)

**Deliverable:** Multi-event pattern detection

**Correlation Rules (10 minimum):**

```python
# Example Rule: Multi-Stage Attack
def detect_multi_stage_attack(events):
    ips_in_portscan = {e.src_ip for e in events if e.type == 'portscan'}
    ips_in_ssh = {e.src_ip for e in events if e.type == 'ssh_failure'}
    ips_in_dns_block = {e.src_ip for e in events if e.type == 'dns_block'}

    coordinated = ips_in_portscan & ips_in_ssh & ips_in_dns_block
    if coordinated:
        return Alert(
            severity="CRITICAL",
            title="Multi-Stage Attack Detected",
            description=f"IP {coordinated} performed port scan, SSH brute force, and DNS lookup in 5-minute window",
            recommendation="Block IP immediately"
        )
```

**More Rules:**
- Compromised IoT device (DNS block + unusual traffic volume + cross-VLAN attempt)
- Data exfiltration (large outbound + unusual port + high-entropy domain)
- Reconnaissance (port scan + service enumeration + vulnerability scan)
- Brute force escalation (failed attempts → successful login → privilege escalation)

**Effort:** 12-16 hours
**Value:** High (connects the dots)

### 3. Device Inventory Database (🟡 MEDIUM)

**Deliverable:** Dynamic device discovery and tracking

**Implementation:**
```python
# agent/device_inventory.py
class DeviceInventory:
    def discover_devices(self):
        # Source 1: UniFi Controller API
        unifi_clients = get_unifi_clients()

        # Source 2: pfSense DHCP leases
        dhcp_leases = get_pfsense_dhcp_leases()

        # Source 3: Active IPs in pfSense logs
        active_ips = get_active_ips_from_logs()

        # Merge and deduplicate
        devices = merge_by_mac_address(unifi_clients, dhcp_leases, active_ips)

        # Store in database
        for device in devices:
            upsert_device(device)

    def detect_rogue_device(self):
        known_devices = get_known_devices()
        current_devices = discover_devices()

        new_devices = current_devices - known_devices
        if new_devices:
            alert(f"New device detected: {new_devices}")

# Run every 15 minutes
```

**Database Schema:**
```sql
CREATE TABLE devices (
    mac_address TEXT PRIMARY KEY,
    ip_address TEXT,
    hostname TEXT,
    device_type TEXT,  -- 'laptop', 'phone', 'iot', 'camera', etc.
    vlan INT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    is_authorized BOOLEAN,
    notes TEXT
);
```

**Effort:** 10-12 hours
**Value:** Medium (enables device-based security)

### 4. Weekly Rollup Reports (🟡 MEDIUM)

**Deliverable:** Automated weekly security summary (as designed in THREAT_ASSESSMENT_PLAN.md)

**Implementation:**
- Follow THREAT_ASSESSMENT_PLAN.md Phase 3 (Weekly Rollup)
- Query past 7 days from SigNoz
- Track persistent attackers (IPs seen 3+ days)
- Compare to previous week (week-over-week trends)
- Generate narrative report with recommendations

**Effort:** 12-15 hours (per threat assessment plan)
**Value:** Medium (strategic visibility)

### 5. Natural Language Query Interface (🟡 MEDIUM)

**Deliverable:** Ask questions in plain English, get answers

**Implementation:**
```python
# agent/tools/nl_query.py
from langchain.agents import create_sql_agent
from langchain_anthropic import ChatAnthropic

@tool
def natural_language_query(question: str) -> str:
    """Ask any question about network security data in plain English."""
    # Agent translates question → SQL → executes → formats result
    sql_agent = create_sql_agent(llm, db=clickhouse_db)
    return sql_agent.invoke(question)

# Examples:
# "Show me all SSH failures from Russia this week"
# "What's the top DNS query from IoT devices?"
# "Has anyone tried to access the validator?"
```

**Effort:** 6-8 hours
**Value:** Medium (accessibility for non-technical users)

### 6. Implement TLS-Encrypted Syslog (🟡 MEDIUM)

**Deliverable:** Secure log transmission (no plaintext)

**Implementation:**
1. Generate CA certificate (self-signed for homelab)
2. Generate client certificates for each log source
3. Configure rsyslog with TLS:
   ```conf
   # rsyslog.conf
   module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1")
   input(type="imtcp" port="6514" StreamDriver.AuthMode="x509/name")
   ```
4. Configure clients to use TLS
5. Test: Verify encrypted connection with tcpdump

**Effort:** 4-6 hours
**Value:** Medium (security best practice)

**Total Medium-Term Effort:** 52-67 hours (3-4 weeks part-time)

## 6.4 Long-Term (1+ Months)

### 1. Machine Learning Anomaly Detection (Advanced)

**Deliverable:** ML models for behavioral analysis

**Approaches:**
- LSTM time-series prediction (predict next hour, alert if actual diverges)
- Autoencoder for log anomaly (compress normal logs, anomalies don't compress well)
- Random Forest for classification (benign vs malicious traffic patterns)

**Effort:** 50-60 hours + ongoing training
**Value:** Very High (state-of-the-art detection)

### 2. Threat Hunting Platform

**Deliverable:** Jupyter notebooks for interactive investigation

**Features:**
- Pre-built queries for common IOCs
- Visualization (Matplotlib, Plotly)
- Hypothesis testing ("Was IP X ever blocked before?")
- Integration with threat intelligence APIs

**Effort:** 20-30 hours
**Value:** High (professional SOC capability)

### 3. Compliance Automation

**Deliverable:** Automated compliance reporting (if needed)

**Standards:**
- PCI-DSS (if processing payments)
- HIPAA (if handling health data)
- GDPR (if EU data subjects)
- SOC 2 (if providing services)

**Effort:** Varies (30-100 hours depending on standard)
**Value:** High (for commercial use)

### 4. Red Team Simulation

**Deliverable:** Internal penetration testing

**Scenarios:**
- Credential stuffing attack (test SSH auto-ban)
- Malware C&C simulation (test DNS blocking)
- Data exfiltration (test anomaly detection)
- Lateral movement (test VLAN isolation)

**Effort:** 20-30 hours per quarter
**Value:** High (find vulnerabilities before attackers)

---

# 7. Advanced Security Features

## 7.1 Zero-Trust Principles Application

**Current State:** Traditional perimeter-based security (VLANs + firewall)

**Zero-Trust Transformation:**

```
Traditional: "Trust but verify" → Inside network = trusted
Zero-Trust: "Never trust, always verify" → All access requires authentication
```

**Zero-Trust Enhancements for First Light:**

1. **Micro-Segmentation** (Beyond VLANs)
   - Current: 4 VLANs (Trusted, IoT, Camera, Validator)
   - Zero-Trust: Per-device firewall rules (pfSense alias lists)
   - Example: Camera VLAN devices can ONLY talk to NVR IP, nothing else

2. **Identity-Based Access Control**
   - Current: IP-based firewall rules
   - Zero-Trust: Certificate-based device authentication
   - Example: Device must present valid TLS client cert to access services

3. **Continuous Verification**
   - Current: Static firewall rules
   - Zero-Trust: Dynamic risk scoring (device behavior affects access)
   - Example: IoT device with high DNS block rate → reduced access

4. **Least Privilege by Default**
   - Current: VLANs have broad access within their tier
   - Zero-Trust: Each device gets minimal required access
   - Example: Smart bulb can reach Home Assistant API, nothing else

**Implementation Roadmap:**

Phase 1 (1-2 weeks):
- Document all legitimate cross-VLAN flows
- Create pfSense alias lists for allowed IPs
- Default-deny everything else

Phase 2 (2-4 weeks):
- Implement device certificates (TLS client auth)
- Set up certificate authority (Vault, Smallstep)

Phase 3 (1-2 months):
- Risk-based access control
- AI agent calculates device risk scores
- pfSense rules dynamically update based on risk

**Effort:** 60-80 hours total
**Value:** High (maximum security posture)

## 7.2 Threat Hunting Capabilities

**Threat Hunting Maturity Model:**

```
Level 0: No hunting (reactive only)
Level 1: Ad-hoc hunting (manual queries)  ← Current
Level 2: Structured hunting (documented hypotheses)
Level 3: Data-driven hunting (ML-assisted)
Level 4: Predictive hunting (proactive)
```

**Building to Level 3-4:**

### Level 2: Structured Hunting Playbooks

**Playbook Example: "Hunt for Data Exfiltration"**

1. **Hypothesis:** Compromised device is slowly exfiltrating data
2. **Data Sources:** pfSense logs, ntopng flows, DNS queries
3. **Queries:**
   ```sql
   -- Find devices with sustained outbound traffic to single destination
   SELECT src_ip, dst_ip, sum(bytes) as total_bytes
   FROM network_flows
   WHERE direction = 'outbound'
     AND timestamp > now() - INTERVAL 24 HOUR
   GROUP BY src_ip, dst_ip
   HAVING total_bytes > 1000000000  -- 1 GB
   ORDER BY total_bytes DESC

   -- Check if destination is unusual (not in top 100 domains)
   -- Check if destination uses non-standard ports
   -- Check if data transfer is encrypted (SSH, HTTPS on unusual ports)
   ```
4. **Indicators:**
   - Large sustained outbound traffic (>1GB/day to single IP)
   - Destination not in Alexa top 1000
   - Traffic outside business hours
   - High-entropy domain name (DGA)
5. **Response:**
   - Isolate device to quarantine VLAN
   - Capture PCAP for forensics
   - Image device for malware analysis

**20 Hunting Playbooks to Create:**
- Insider threat (unusual file access patterns)
- Ransomware preparation (mass file enumeration)
- C&C communication (beaconing detection)
- Lateral movement (unusual cross-VLAN access)
- Privilege escalation (sudo/root access attempts)
- Persistence mechanisms (new scheduled tasks, cronjobs)
- Reconnaissance (port scanning from inside)
- Supply chain attack (compromised update mechanism)

**Effort:** 30-40 hours (20 playbooks × 1.5-2 hours each)

### Level 3: Data-Driven Hunting (AI-Assisted)

**Hunt Candidate Generation:**

```python
# AI agent suggests what to hunt for based on data
class HuntCandidateGenerator:
    def generate_candidates(self):
        # Find statistical outliers
        outliers = detect_outliers(all_devices)

        # Find rare events
        rare_events = find_rare_patterns(logs)

        # Find new behaviors
        new_behaviors = compare_to_baseline(current, historical)

        candidates = []
        for device in outliers:
            candidates.append({
                "device": device,
                "reason": f"Traffic volume {z_score}x normal",
                "recommended_hunt": "data_exfiltration_playbook"
            })

        return candidates

# Outputs:
# "Device 192.168.2.45 has 10x normal DNS queries → Hunt for C&C"
# "Device 192.168.1.99 connected to new IP range → Hunt for lateral movement"
```

**Effort:** 20-30 hours (after anomaly detection is built)

### Level 4: Predictive Hunting

**Predict where threats will appear:**
- Time-series forecasting of attack patterns
- "SSH brute force typically increases on weekends" → proactive monitoring
- "IoT devices usually compromised 30 days after firmware release" → patch urgency
- Threat intelligence correlation (attacker TTP → predict next move)

**Effort:** 40-50 hours (research + ML models)

## 7.3 Incident Response Readiness

**Current Incident Response Capability:** 3/10 (detection good, response poor)

**NIST Incident Response Lifecycle:**

```
1. Preparation → 2. Detection → 3. Analysis → 4. Containment → 5. Eradication → 6. Recovery → 7. Lessons Learned
```

**Current State Assessment:**

| Phase | Score | Notes |
|-------|-------|-------|
| 1. Preparation | 5/10 | Tools ready, no formal plan or playbooks |
| 2. Detection | 8/10 | Excellent (SigNoz, CrowdSec) |
| 3. Analysis | 4/10 | Manual investigation, no forensics tools |
| 4. Containment | 2/10 | Manual IP ban, no quarantine VLAN |
| 5. Eradication | 3/10 | Unclear process (reimage? update?) |
| 6. Recovery | 4/10 | Docker restart, no validated backups |
| 7. Lessons Learned | 1/10 | No post-incident review process |

**Improvement Plan:**

### Phase 1: Preparation (1 week)

**Create Incident Response Playbooks:**

```markdown
# Playbook: Compromised IoT Device

## Detection Triggers
- AdGuard blocks malware domain from IoT VLAN
- ntopng alerts on unusual traffic volume
- Device attempts cross-VLAN access

## Immediate Actions (5 minutes)
1. Identify device MAC and IP from logs
2. Block device on pfSense (create firewall rule)
3. Notify via Telegram: "Device {name} quarantined"

## Containment (15 minutes)
1. Move device to quarantine VLAN (VLAN 99)
2. Capture PCAP of device traffic (tcpdump)
3. Query historical logs (past 7 days of device activity)

## Analysis (30 minutes)
1. Check DNS queries (malware domains?)
2. Check firewall logs (C&C IPs?)
3. Check ntopng flows (data exfiltration?)
4. Correlate with threat intelligence (known botnet?)

## Eradication (variable)
- Option 1: Factory reset device
- Option 2: Firmware update
- Option 3: Decommission (if unsalvageable)

## Recovery
1. Test device in quarantine VLAN for 24 hours
2. If clean, move back to IoT VLAN
3. Add to monitoring watchlist (high frequency checks)

## Lessons Learned
1. Document root cause
2. Update firewall rules to prevent recurrence
3. Consider firmware update policy
```

**20 Playbooks to Create:**
- SSH brute force
- Compromised IoT device
- Ransomware detected
- Data exfiltration
- DDoS attack
- Insider threat
- Validator offline
- Disk space critical
- Service outage
- Network equipment failure

**Effort:** 20-30 hours

### Phase 2: Forensics Tools (2 weeks)

**Deploy Forensics Toolkit:**
1. **PCAP Capture** (tcpdump, Wireshark)
2. **Memory Forensics** (Volatility for device analysis)
3. **Log Aggregator** (Already have SigNoz)
4. **Timeline Analysis** (Plaso for event reconstruction)
5. **Artifact Collection** (Velociraptor for endpoint data)

**Effort:** 10-15 hours

### Phase 3: Automated Containment (2 weeks)

**Build Quarantine System:**
```python
@tool
def quarantine_device(ip: str, mac: str) -> str:
    """Automatically quarantine a device to isolated VLAN."""
    # 1. Add pfSense firewall rule (block all traffic from IP)
    pfsense_api.block_ip(ip)

    # 2. Move device to quarantine VLAN (UniFi API)
    unifi_api.assign_client_to_vlan(mac, vlan_id=99)

    # 3. Start PCAP capture
    start_tcpdump(interface="vlan99", filter=f"host {ip}")

    # 4. Notify
    telegram.send(f"🚨 Device {ip} quarantined. PCAP capturing.")

    return f"Device {ip} isolated and under observation."
```

**Effort:** 12-16 hours

**Total Incident Response Effort:** 42-61 hours

## 7.4 Security Orchestration (SOAR-like)

**Security Orchestration, Automation, and Response (SOAR):**

```
SOAR = Detection (SIEM) + Automation (Playbooks) + Response (Actions)
```

**SOAR for First Light:**

### Orchestration Workflows

**Workflow 1: Persistent SSH Attacker**
```
Trigger: CrowdSec decision (ban IP)
    ↓
Action 1: pfSense bouncer blocks IP (auto)
    ↓
Action 2: Query threat intel (AbuseIPDB, VirusTotal)
    ↓
Action 3: Generate incident report (PDF)
    ↓
Action 4: Send to Telegram with threat context
    ↓
Decision: If confidence > 90%, extend ban to 7 days
```

**Workflow 2: Compromised IoT Device**
```
Trigger: AdGuard blocks malware domain from IoT device
    ↓
Action 1: Alert via Telegram (WARNING level)
    ↓
Action 2: Query device history (past 7 days)
    ↓
Action 3: AI agent analyzes patterns
    ↓
Decision: If "likely compromised", quarantine device
    ↓
Action 4: Move to quarantine VLAN (auto)
    ↓
Action 5: Start PCAP capture
    ↓
Action 6: Notify with remediation steps
```

**Workflow 3: Disk Space Critical**
```
Trigger: Disk usage > 85%
    ↓
Action 1: Alert via Telegram
    ↓
Action 2: Calculate oldest safe-to-delete logs
    ↓
Decision: If > 90%, auto-delete logs older than 3 days
    ↓
Action 3: Delete old logs (auto)
    ↓
Action 4: Notify deletion summary
```

**Implementation:**
- Use LangGraph for workflow orchestration
- Each workflow is a LangGraph graph
- Human-in-the-loop for high-risk actions

**Effort:** 30-40 hours (10 workflows × 3-4 hours each)

## 7.5 Compliance Monitoring

**Homelab Compliance Focus:**
- Not regulated (no PCI-DSS, HIPAA, SOC 2)
- Self-imposed standards (CIS, NIST)
- Validator financial accountability (track earnings)

**Compliance Automation:**

### 1. CIS Controls Audit Report (Monthly)

```python
def generate_cis_audit_report():
    checks = {
        "1.1": check_asset_inventory_exists(),
        "1.2": check_asset_inventory_updated_90d(),
        "7.1": check_centralized_logging(),
        "8.2": check_log_retention_policy(),
        "12.4": check_firewall_rules_documented(),
        # ... 50 more checks
    }

    score = sum(checks.values()) / len(checks) * 10

    report = f"""
    CIS Controls Audit - {today}
    Overall Score: {score}/10

    Passing: {passing_count}
    Failing: {failing_count}

    Failures:
    - 2.1: Software inventory missing → Action: Implement
    - 5.1: MFA not enforced → Action: Enable
    """

    return report
```

**Effort:** 20-30 hours (build audit script)

### 2. Validator Earnings Report (Weekly)

```python
def generate_validator_earnings_report():
    # Query beacon chain API for validator balance
    current_balance = get_validator_balance()
    last_week_balance = get_balance_7_days_ago()

    earnings_7d = current_balance - last_week_balance
    apr = calculate_apr(earnings_7d)

    report = f"""
    Validator Earnings Report - Week {week_number}

    Starting Balance: {last_week_balance} ETH
    Ending Balance: {current_balance} ETH
    Earnings: +{earnings_7d} ETH (${earnings_7d * eth_price} USD)

    APR: {apr}%
    Attestation Effectiveness: {attestation_pct}%
    Missed Attestations: {missed_count}
    Downtime: {downtime_minutes} minutes

    Status: {"✅ ON TARGET" if apr > 4.5 else "⚠️ BELOW TARGET"}
    """

    return report
```

**Effort:** 4-6 hours

---

# 8. Prioritized Action Plan

## 8.1 Quick Wins (This Week: 3-4 hours)

| Priority | Action | Effort | Impact | Owner |
|----------|--------|--------|--------|-------|
| 🔴 1 | Enable CrowdSec pfSense bouncer | 1-2h | CRITICAL | Sysadmin |
| 🔴 2 | Create cross-VLAN traffic alert | 30m | CRITICAL | Sysadmin |
| 🟠 3 | Add disk space critical alert | 30m | HIGH | Sysadmin |
| 🟠 4 | Add SSH brute force alert | 30m | HIGH | Sysadmin |
| 🟠 5 | Add validator offline alert | 30m | HIGH | Sysadmin |

**Total: 3-4 hours**
**Impact: Transforms security posture from reactive to proactive**

## 8.2 Short-Term (1-2 Weeks: 28-38 hours)

| Priority | Action | Effort | Impact | Dependencies |
|----------|--------|--------|--------|--------------|
| 🟠 1 | Integrate Ethereum validator metrics | 3-4h | HIGH | Telegraf config |
| 🔴 2 | AdGuard DNS query log integration | 4-6h | CRITICAL | API or syslog |
| 🟠 3 | Build AI agent log query tools (8 tools) | 8-12h | HIGH | SigNoz API |
| 🟠 4 | Implement daily threat assessment report | 6-8h | HIGH | Agent tools |
| 🟠 5 | pfSense API integration | 2-3h | HIGH | API credentials |
| 🟡 6 | Create baseline metrics database | 4-5h | MEDIUM | SQLite |

**Total: 28-38 hours (1-2 weeks part-time)**

## 8.3 Medium-Term (2-4 Weeks: 52-67 hours)

| Priority | Action | Effort | Impact | Dependencies |
|----------|--------|--------|--------|--------------|
| 🟠 1 | Statistical anomaly detection engine | 8-10h | HIGH | Baseline DB |
| 🟠 2 | Threat correlation engine (10 rules) | 12-16h | HIGH | Agent tools |
| 🟡 3 | Device inventory database | 10-12h | MEDIUM | UniFi/pfSense API |
| 🟡 4 | Weekly rollup reports | 12-15h | MEDIUM | Daily reports |
| 🟡 5 | Natural language query interface | 6-8h | MEDIUM | LangChain SQL |
| 🟡 6 | TLS-encrypted syslog | 4-6h | MEDIUM | Certs + rsyslog config |

**Total: 52-67 hours (2-4 weeks part-time)**

## 8.4 Long-Term (1+ Months: 130-170 hours)

| Priority | Action | Effort | Impact | Phase |
|----------|--------|--------|--------|-------|
| 🟠 1 | ML anomaly detection (LSTM, autoencoder) | 50-60h | VERY HIGH | Research + impl |
| 🟡 2 | Threat hunting platform (Jupyter) | 20-30h | HIGH | Advanced SOC |
| 🟡 3 | Zero-trust micro-segmentation | 60-80h | HIGH | Identity + policy |

**Total: 130-170 hours (2-3 months part-time)**

## 8.5 Total Effort Summary

| Phase | Timeline | Effort | Key Deliverables |
|-------|----------|--------|------------------|
| **Quick Wins** | This week | 3-4h | Auto-ban, critical alerts |
| **Short-Term** | 1-2 weeks | 28-38h | Validator metrics, DNS logs, AI agent operational, daily reports |
| **Medium-Term** | 2-4 weeks | 52-67h | Anomaly detection, correlation, weekly reports |
| **Long-Term** | 1+ months | 130-170h | ML models, threat hunting, zero-trust |
| **TOTAL** | 3 months | **213-279 hours** | Professional-grade security operations |

**At 10 hours/week:** 21-28 weeks (5-7 months)
**At 20 hours/week:** 11-14 weeks (2.5-3.5 months)
**At 40 hours/week (full-time):** 5-7 weeks (1-2 months)

---

# 9. AI/ML Roadmap

## Phase 1: Foundation (Current → 2 Weeks)

**Goal:** Functional AI agent with comprehensive data access

**Deliverables:**
1. ✅ Agent framework (LangGraph, ChatAnthropic) — DONE
2. 🚧 8+ SigNoz log query tools — IN PROGRESS
3. 🚧 AdGuard metrics tools (5 tools) — DONE
4. 🚧 Daily threat assessment report generator — PLANNED
5. 🚧 Basic statistical baseline tracking — PLANNED

**Effort:** 20-25 hours
**Success Criteria:** AI agent can answer "What were the top 10 firewall blocks today?"

## Phase 2: Intelligence (Weeks 3-4)

**Goal:** Anomaly detection and threat correlation

**Deliverables:**
1. Statistical baseline models (7-day, 30-day rolling)
2. Z-score anomaly detection (5+ metrics monitored)
3. Threat correlation rules (10 patterns minimum)
4. Weekly rollup reports (narrative + trends)
5. Natural language query interface (English → SQL)

**Effort:** 30-35 hours
**Success Criteria:** AI detects a 3-sigma spike in SSH failures and correlates with firewall blocks from same IP

## Phase 3: Automation (Month 2)

**Goal:** Proactive security operations with human oversight

**Deliverables:**
1. Automated threat response (CrowdSec → pfSense bouncer)
2. Device behavior baselines (per-device traffic profiles)
3. Predictive disk space alerts (forecasting)
4. Interactive Telegram queries ("/ask why was IP X blocked?")
5. Incident report generation (automated post-incident summaries)

**Effort:** 40-50 hours
**Success Criteria:** AI auto-bans persistent attacker within 5 minutes of detection, generates incident report

## Phase 4: Advanced ML (Month 3+)

**Goal:** State-of-the-art ML-based threat detection

**Deliverables:**
1. LSTM time-series anomaly detection (predict next hour, alert on deviation)
2. Autoencoder for log anomaly (unsupervised learning)
3. DGA domain detection (Random Forest classifier)
4. Behavioral device clustering (K-means, identify device types)
5. Threat intelligence enrichment (auto-query AbuseIPDB, VirusTotal)

**Effort:** 80-100 hours
**Success Criteria:** ML model detects data exfiltration 30 minutes before statistical anomaly detection would

## Phase 5: Autonomous Operations (Month 6+, Future Vision)

**Goal:** Fully autonomous security operations with human audit

**Deliverables:**
1. Autonomous incident response (detect → contain → eradicate → recover)
2. Predictive threat modeling (forecast attack vectors)
3. Self-tuning alert thresholds (RL-based optimization)
4. Continuous security posture scoring (real-time risk dashboard)
5. Simulation-based training (red team simulations in isolated environment)

**Effort:** 150-200 hours
**Success Criteria:** System operates for 30 days without human intervention, all incidents handled autonomously

---

# 10. Best Practices Checklist

## What We're Doing Well ✅

- ✅ Centralized logging with 850k logs/day collection
- ✅ VLAN segmentation (Trusted/IoT/Isolated/DMZ)
- ✅ Defense-in-depth (firewall + IDS + DNS filtering)
- ✅ Infrastructure as Code (docker-compose, topology.yaml)
- ✅ Structured log parsing (pfSense, ntopng, UniFi)
- ✅ Noise filtering (80-90% reduction on verbose sources)
- ✅ Fast query capability (ClickHouse columnar storage)
- ✅ Threat intelligence integration (CrowdSec community)
- ✅ Professional observability stack (SigNoz Enterprise)
- ✅ Comprehensive documentation (CLAUDE.md, threat plan)
- ✅ Security-focused design (Camera VLAN isolated)
- ✅ Modern OTel standards (semantic conventions)

## What Needs Improvement ⚠️

- ⚠️ No multi-factor authentication on management interfaces
- ⚠️ SNMP v2c (weak authentication) — upgrade to v3
- ⚠️ No log encryption in transit (plaintext syslog)
- ⚠️ Secrets in .env files (not secret manager)
- ⚠️ No backup validation (unknown if restore works)
- ⚠️ Single Docker host (SPOF)
- ⚠️ Manual incident response (slow MTTR)
- ⚠️ No change management log (unified changelog)
- ⚠️ No penetration testing (internal red team)
- ⚠️ Limited alert rules (detection without alerting)

## What's Missing ❌

- ❌ Automated threat response (CrowdSec bouncer)
- ❌ AdGuard DNS query logs (critical gap)
- ❌ Cross-VLAN traffic alerting (isolation breach detection)
- ❌ Validator metrics (financial monitoring)
- ❌ Anomaly detection (statistical or ML)
- ❌ AI agent operational (framework exists, tools don't)
- ❌ Log integrity verification (tamper detection)
- ❌ Device inventory database (dynamic discovery)
- ❌ pfSense API integration (automated firewall control)
- ❌ Threat correlation engine (multi-event patterns)
- ❌ Natural language query interface (English → SQL)
- ❌ Automated reporting (daily/weekly digests)
- ❌ Vulnerability scanning (Nessus, OpenVAS)
- ❌ Forensics toolkit (PCAP, memory analysis)

---

# 11. Advanced Capabilities Roadmap

## Threat Hunting Platform (Month 2-3)

**Vision:** Interactive Jupyter environment for security investigations

**Components:**
1. Pre-built notebooks for common hunts (data exfiltration, lateral movement, C&C)
2. Integration with SigNoz ClickHouse (direct SQL queries)
3. Visualization libraries (Plotly, Seaborn for timeline analysis)
4. Threat intelligence API integrations (AbuseIPDB, VirusTotal, Shodan)
5. Hypothesis testing framework (document hunt results)

**Use Cases:**
- "Hunt for DNS C&C beaconing" (periodic queries to same domain)
- "Hunt for data exfiltration" (sustained outbound traffic)
- "Hunt for lateral movement" (cross-VLAN access patterns)

**Effort:** 20-30 hours

## Security Orchestration (Month 3-4)

**Vision:** SOAR-like automation for incident response

**Components:**
1. Workflow engine (LangGraph orchestrates response playbooks)
2. 20 response playbooks (automated remediation steps)
3. Human-in-the-loop approvals (high-risk actions require confirm)
4. Audit trail (log all automated actions)
5. Rollback capability (undo automated changes)

**Example Workflows:**
- Persistent attacker: Detect → Ban IP → Query threat intel → Extend ban if high confidence
- Compromised device: Detect → Quarantine VLAN → PCAP capture → Analyze → Remediate
- Disk space critical: Detect → Auto-delete old logs → Notify → Prevent recurrence

**Effort:** 30-40 hours

## Compliance Automation (Month 4-5)

**Vision:** Automated compliance reporting and evidence collection

**Components:**
1. CIS Controls audit script (monthly compliance score)
2. NIST CSF assessment (automated gap analysis)
3. Evidence collection (screenshots, log exports, config backups)
4. Attestation reports (for audits or certifications)
5. Validator earnings tracking (tax reporting)

**Deliverables:**
- Monthly CIS Controls report card (score + remediation actions)
- Quarterly NIST CSF assessment (progress tracking)
- Annual validator earnings report (for tax purposes)

**Effort:** 20-30 hours

## Red Team Simulation (Ongoing)

**Vision:** Internal adversary simulation to validate defenses

**Scenarios (Quarterly):**
1. **Credential Stuffing Attack**
   - Simulate: Brute force SSH from Tor exit node
   - Expected Detection: CrowdSec alert within 5 minutes
   - Expected Response: Auto-ban within 10 minutes (if bouncer enabled)

2. **Malware C&C Communication**
   - Simulate: IoT device queries known malware domain
   - Expected Detection: AdGuard block + alert
   - Expected Response: Device flagged for investigation

3. **Data Exfiltration**
   - Simulate: Sustained 10 Mbps upload to unusual IP
   - Expected Detection: Anomaly detection within 30 minutes
   - Expected Response: Alert to Telegram

4. **Lateral Movement**
   - Simulate: Camera VLAN device attempts cross-VLAN connection
   - Expected Detection: Instant (cross-VLAN alert)
   - Expected Response: Critical alert to Telegram

**Effort:** 8-10 hours per quarter

---

# Conclusion

## Summary of Findings

First Light represents a **strong foundation** for network observability with professional-grade tooling and security-conscious architecture. The system excels at **comprehensive data collection** (850k logs/day, 8+ sources) and demonstrates **best practices** in log parsing, noise filtering, and VLAN segmentation.

However, the stack is currently in **detection-only mode** with three critical gaps:

1. **No automated threat response** (CrowdSec detects but doesn't block)
2. **Major data source gaps** (AdGuard DNS, validator metrics)
3. **AI agent not operational** (framework exists, functionality doesn't)

## Security Posture Rating: 7.5/10

**Breakdown:**
- Detection: 8/10 (Excellent collection, good parsing)
- Response: 2/10 (Manual only, slow MTTR)
- Architecture: 8/10 (Strong design, well-segmented)
- Automation: 3/10 (Infrastructure automated, security isn't)

## Top 3 Priority Recommendations

1. **Enable Automated Threat Response (1-2 hours)**
   - Install CrowdSec pfSense bouncer
   - Create cross-VLAN traffic alert
   - Impact: Immediate improvement from detection-only to active defense

2. **Integrate Missing Data Sources (8-12 hours)**
   - AdGuard DNS query logs (critical for DNS-based threats)
   - Validator metrics (financial monitoring)
   - pfSense API (programmatic control)

3. **Operationalize AI Agent (20-30 hours)**
   - Build SigNoz log query tools
   - Implement daily threat assessment reports
   - Deploy statistical anomaly detection

## Path to MEGA_SECURE

To achieve best-in-class homelab security:

**Quick Wins (Week 1):** Auto-ban attackers, critical alerts
**Foundation (Weeks 2-4):** Data source integration, AI agent operational
**Intelligence (Month 2):** Anomaly detection, threat correlation
**Automation (Month 3):** Automated response, predictive analytics
**Advanced (Month 6+):** ML models, threat hunting platform, zero-trust

**Total Effort:** 213-279 hours over 3-6 months

## Final Assessment

First Light has **excellent bones** with professional architecture and comprehensive data collection. The primary investment needed is in **automation and intelligence** — transforming collected data into automated security operations.

The threat assessment plan (THREAT_ASSESSMENT_PLAN.md) is well-designed and should be implemented as Phase 1. Combined with the quick wins (CrowdSec bouncer, critical alerts), First Light can rapidly evolve from a monitoring platform to a proactive security operations system.

**Recommended Next Steps:**

1. This week: Implement all 5 quick wins (3-4 hours)
2. Next 2 weeks: AdGuard + validator integration + daily reports (20-30 hours)
3. Month 2: Anomaly detection + correlation engine (30-40 hours)
4. Ongoing: Quarterly security reviews + red team simulations

With these investments, First Light will achieve **MEGA_SECURE status** — a homelab security posture that rivals professional enterprise SOCs.

---

**End of Report**

*This audit was conducted with the assistance of Claude Sonnet 4.5, analyzing all available documentation, code, and configuration files to provide a comprehensive security assessment.*
