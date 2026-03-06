# Threat Assessment and Reporting Strategy
## First Light Network Observability Stack

**Version:** 1.0
**Created:** March 4, 2026
**Author:** Security Analyst (AI-Assisted)

---

## Table of Contents

1. [Daily Threat Assessment Email](#1-daily-threat-assessment-email)
2. [Weekly Rollup Email](#2-weekly-rollup-email)
3. [Report Storage Strategy](#3-report-storage-strategy)
4. [Highest Value Metrics](#4-highest-value-metrics)
5. [Implementation Priority](#5-implementation-priority)

---

## 1. Daily Threat Assessment Email

### Email Format

**Subject Line Format:**
```
[First Light] Daily Threat Assessment - {date} - {status_emoji} {summary}
```

Examples:
- `[First Light] Daily Threat Assessment - Mar 4, 2026 - ✅ All Clear`
- `[First Light] Daily Threat Assessment - Mar 4, 2026 - ⚠️ 3 Warnings`
- `[First Light] Daily Threat Assessment - Mar 4, 2026 - 🔴 CRITICAL: Device Unreachable`

### Email Body Structure

```markdown
# Daily Threat Assessment
**Date:** {date}
**Status:** {status_emoji} {overall_status}
**Report Generated:** {timestamp}

---

## Executive Summary

{2-3 sentence summary of the day's security posture}

Example: "Your network is operating normally with no critical threats detected.
AdGuard blocked 247 suspicious domains, and pfSense rejected 1,832 unauthorized
connection attempts. All infrastructure is healthy."

---

## Key Metrics (24h)

### Network Security
- 🛡️ **Firewall Blocks:** {count} ({change_vs_avg})
  - Top source: {top_ip} ({count} attempts)
  - Top target port: {port} ({protocol})
- 🚫 **DNS Blocks (AdGuard):** {count} malicious/ad domains
  - High-risk domains: {high_risk_count}
  - Top blocked: {top_domain}
- ⚠️ **Flow Alerts (ntopng):** {critical_count} critical, {warning_count} warnings
  - Most concerning: {top_alert_type}

### Infrastructure Health
- 💾 **Disk Usage:** {percent}% ({trend})
- 📊 **Network Bandwidth:** Peak {peak_mbps} Mbps on {interface}
- 🔌 **Interface Errors:** {error_count} ({devices_affected} devices)
- ⏱️ **Service Uptime:** All services operational ({uptime_days} days)

### ETH Validator (if applicable)
- ✅ **Attestation Effectiveness:** {percent}%
- 📈 **Balance:** {eth_balance} ETH ({change_24h})
- 👥 **Peer Count:** {peers} consensus, {execution_peers} execution
- 🔄 **Sync Status:** {status}

---

## Notable Events

{Only include if there are events worth mentioning}

### Security Events
1. **{event_type}** - {timestamp}
   - Source: {source_ip} ({geo_location})
   - Target: {target} ({service})
   - Action: {action_taken}
   - Context: {why_this_matters}

2. **SSH Failed Login Spike** - 14:32 UTC
   - Source: 185.220.101.42 (Tor exit node)
   - Target: docker.mcducklabs.com:22
   - Action: Blocked after 3 attempts, CrowdSec IP banned
   - Context: Automated scanning, no credential compromise

### Infrastructure Events
1. **High Interface Utilization** - switch port 8 - 18:45 UTC
   - Traffic: 850 Mbps (sustained 10 minutes)
   - Source: NAS backup to Proxmox
   - Context: Scheduled backup, normal pattern

2. **Container Restart** - fl-snmp-exporter - 06:12 UTC
   - Reason: Health check timeout (known issue)
   - Impact: 5-minute gap in SNMP metrics
   - Status: Auto-recovered

---

## Cross-VLAN Traffic Alerts

{Only if detected - this is a high-priority security concern}

⚠️ **Unexpected traffic detected between isolated VLANs:**
- {vlan_source} → {vlan_dest}: {protocol} {port}
- Source device: {device} ({purpose})
- Packets: {count}
- **Action Required:** Investigate immediately - VLANs should not communicate

---

## Action Items

{Only if actions are required - DO NOT create noise}

### Critical (Immediate)
- None ✅

### Warning (Review within 24h)
- None ✅

### Info (Low Priority)
- Review high bandwidth usage pattern on switch port 8 (backup schedule optimization)

---

## Trend Indicators

{Compare to 7-day average}

- Firewall blocks: {percent_change}% {vs_average}
- DNS blocks: {percent_change}% {vs_average}
- Network bandwidth: {percent_change}% {vs_average}
- Disk growth: {gb_per_day} GB/day (projected {days_remaining} days remaining)

---

**Report ID:** {uuid}
**Query Window:** {start_time} to {end_time} UTC
**Next Report:** {tomorrow} 08:00 UTC
```

### Design Principles

1. **Concise**: Readable in 2-3 minutes
2. **Actionable**: Only flag items requiring action
3. **Context**: Explain WHY something matters
4. **Comparative**: Show trends vs normal patterns
5. **Visual**: Use emojis/formatting for quick scanning
6. **Honest**: Don't cry wolf - "All Clear" is a valid status

### When to Send

- **Time:** 08:00 local time (after overnight activity)
- **Trigger:** Cron job (daily)
- **Skip:** Never (even if "all clear", send confirmation)

---

## 2. Weekly Rollup Email

### Email Format

**Subject Line Format:**
```
[First Light] Weekly Security Rollup - Week of {start_date} - {trend_emoji}
```

Examples:
- `[First Light] Weekly Security Rollup - Week of Feb 26 - 📊 Stable`
- `[First Light] Weekly Security Rollup - Week of Feb 26 - 📈 Threat Increase`
- `[First Light] Weekly Security Rollup - Week of Feb 26 - 📉 Quieter Week`

### Email Body Structure

```markdown
# Weekly Security Rollup
**Week:** {start_date} to {end_date}
**Status:** {overall_trend}
**Report Generated:** {timestamp}

---

## Executive Summary

{3-5 sentence summary of the week's security posture and trends}

Example: "This week showed typical homelab security patterns with increased
automated scanning from Eastern Europe. A new persistent scanner (IP 45.xxx.xxx.xxx)
was identified and banned by CrowdSec. Infrastructure remained healthy with no
service disruptions. Disk usage continues at expected rate (~6 GB/day)."

---

## Week in Numbers

### Security Metrics (7-day totals)
| Metric | This Week | Last Week | Change | 7-Day Avg |
|--------|-----------|-----------|--------|-----------|
| Firewall Blocks | {count} | {last_week} | {change} | {avg}/day |
| DNS Blocks | {count} | {last_week} | {change} | {avg}/day |
| High-Risk DNS Blocks | {count} | {last_week} | {change} | {avg}/day |
| Critical Flow Alerts | {count} | {last_week} | {change} | {avg}/day |
| Failed SSH Attempts | {count} | {last_week} | {change} | {avg}/day |
| Unique Attacker IPs | {count} | {last_week} | {change} | - |

### Infrastructure Metrics
| Metric | Status | Trend |
|--------|--------|-------|
| Disk Usage | {percent}% | {trend_arrow} {gb} GB used |
| Peak Bandwidth | {mbps} Mbps | {trend_arrow} {when} |
| Interface Errors | {count} total | {status_emoji} {devices} |
| Average CPU (Proxmox) | {percent}% | {trend_arrow} |
| ETH Validator Effectiveness | {percent}% | {trend_arrow} |

---

## Threat Analysis

### New Threats This Week
{Only attackers/patterns not seen before}

1. **Persistent Scanner: 45.xxx.xxx.xxx**
   - First seen: {date} {time}
   - Pattern: Port scanning (22, 80, 443, 8080, 8443)
   - Attempts: {count} over {duration}
   - Geography: {country}
   - Status: Banned by CrowdSec on {date}
   - Persistence: Returned {retry_count} times with new IPs

2. **Malware Domain Spike: malicious-cdn.example.com**
   - First seen: {date}
   - Requesting device: IoT VLAN device {ip} ({purpose})
   - Attempts: {count}
   - Risk: High (known C&C domain)
   - Action: Blocked by AdGuard, device flagged for investigation

### Recurring Threats
{Known bad actors that keep trying}

| IP/Domain | Type | This Week | Total Blocked | Last Seen | Status |
|-----------|------|-----------|---------------|-----------|--------|
| 192.0.2.1 | SSH Brute Force | 342 | 2,847 | {date} | Active |
| evil.example.com | Phishing | 28 | 156 | {date} | Persistent |

---

## Notable Patterns & Anomalies

### Pattern Changes
1. **SSH Attempts Increased 34%**
   - Normal: ~200/day → This week: ~270/day
   - Source: Mostly Tor exit nodes (unchanged pattern)
   - Assessment: Global scanning increase, not targeted
   - Action: Monitor, no change needed

2. **Weekend Bandwidth Spike**
   - Saturday 19:00-23:00: Peak 780 Mbps (normal: <200 Mbps)
   - Source: Trusted VLAN → IoT VLAN (Plex streaming to TV)
   - Assessment: Legitimate usage (4K movie marathon)
   - Action: None

3. **AdGuard High-Risk Blocks Down 60%**
   - Normal: ~50/day → This week: ~20/day
   - Assessment: Positive trend, fewer infected/malicious requests
   - Possible cause: Recent device firmware updates on IoT VLAN
   - Action: Monitor for sustained improvement

---

## Infrastructure Trends

### Disk Usage Trajectory
- **Current:** {percent}% ({gb} GB used)
- **Growth Rate:** {gb_per_day} GB/day (7-day average)
- **Projected Full:** {date} (~{days} days)
- **Status:** {status} (retention policy working as expected)

### Service Reliability
- **Uptime:** {percent}% (all services)
- **Restarts:** {count} total
  - Planned: {planned_count} (maintenance)
  - Unplanned: {unplanned_count}
- **Data Gaps:** {count} gaps > 5 minutes
- **Assessment:** {status}

### Network Performance
- **Peak Hour:** {day} {time} - {mbps} Mbps
- **Quietest Hour:** {day} {time} - {mbps} Mbps
- **Top Talker:** {device} - {total_gb} GB transferred
- **Port Errors:** {count} (devices: {device_list})

---

## ETH Validator Performance (if applicable)

### Attestation Summary
- **Effectiveness:** {percent}% (target: >98%)
- **Missed Attestations:** {count}/week
- **Proposals:** {assigned} assigned, {successful} successful
- **Downtime:** {duration} (events: {count})

### Balance & Rewards
- **Starting Balance:** {eth} ETH
- **Ending Balance:** {eth} ETH
- **Net Change:** {change} ETH ({change_usd} USD equivalent)
- **Rewards Rate:** {apr}% APR (annualized)

### Health Indicators
- **Peer Count:** Avg {consensus} consensus, {execution} execution
- **Sync Status:** {percent}% (gaps: {count})
- **Validator Status:** {status}

---

## Security Recommendations

### Immediate Actions Required
{Only if critical issues detected}
- None this week ✅

### Consider This Week
1. **Review IoT Device: {device_ip}**
   - Reason: Attempted connection to known malware domain
   - Risk: Potentially compromised firmware
   - Action: Check for firmware updates, consider network isolation
   - Priority: Medium

2. **Rotate Credentials for External Services**
   - Last rotation: {date} ({days} days ago)
   - Policy: Rotate every 90 days
   - Affected: AdGuard API, ntopng, Proxmox
   - Priority: Low

### Long-Term Improvements
1. Consider CrowdSec bouncer for pfSense (automate IP blocking)
2. Add GeoIP blocking for regions with no legitimate traffic
3. Implement VLAN traffic flow monitoring (baseline cross-VLAN traffic)

---

## Comparison to Previous Weeks

### 4-Week Trend Summary

| Week | Firewall Blocks | DNS Blocks | Critical Alerts | Status |
|------|-----------------|------------|-----------------|--------|
| {date} (this week) | {count} | {count} | {count} | {emoji} |
| {date} | {count} | {count} | {count} | {emoji} |
| {date} | {count} | {count} | {count} | {emoji} |
| {date} | {count} | {count} | {count} | {emoji} |

**Assessment:** {trend_analysis}

---

## Appendix: Daily Summaries

{Brief one-line summary per day}

- **Monday {date}:** All clear, {firewall_blocks} blocks, {dns_blocks} DNS blocks
- **Tuesday {date}:** SSH spike (Tor scanning), otherwise normal
- **Wednesday {date}:** All clear, routine activity
- **Thursday {date}:** New scanner 45.xxx.xxx.xxx identified and banned
- **Friday {date}:** All clear, low activity day
- **Saturday {date}:** Weekend bandwidth spike (Plex), normal pattern
- **Sunday {date}:** All clear, minimal activity

---

**Report ID:** {uuid}
**Query Window:** {start_date} 00:00 UTC to {end_date} 23:59 UTC
**Next Report:** {next_week_date}
```

### Design Principles

1. **Analytical**: Focus on trends and patterns, not individual events
2. **Comparative**: Always compare to previous weeks
3. **Predictive**: Project future issues (disk space, threat trends)
4. **Strategic**: Recommend improvements, not just report status
5. **Historical**: Track recurring threats and persistent patterns
6. **Educational**: Explain security concepts for homelab admin

### When to Send

- **Time:** Sunday 20:00 local time (end of week review)
- **Trigger:** Cron job (weekly)
- **Skip:** Never (even quiet weeks are worth documenting)

---

## 3. Report Storage Strategy

### Storage Architecture

```
/opt/first-light/reports/
├── daily/
│   ├── 2026/
│   │   ├── 03/
│   │   │   ├── 2026-03-01_daily_report.md
│   │   │   ├── 2026-03-01_daily_report.html
│   │   │   ├── 2026-03-01_metrics.json
│   │   │   ├── 2026-03-02_daily_report.md
│   │   │   ├── 2026-03-02_daily_report.html
│   │   │   ├── 2026-03-02_metrics.json
│   │   │   └── ...
├── weekly/
│   ├── 2026/
│   │   ├── W09_2026-02-24_to_2026-03-02_weekly_rollup.md
│   │   ├── W09_2026-02-24_to_2026-03-02_weekly_rollup.html
│   │   ├── W09_2026-02-24_to_2026-03-02_metrics.json
│   │   └── W10_2026-03-03_to_2026-03-09_weekly_rollup.md
├── metrics/
│   ├── daily_metrics.db (SQLite)
│   ├── weekly_metrics.db (SQLite)
│   └── trend_snapshots/
│       ├── 2026-03-01_snapshot.json
│       └── ...
└── attachments/
    ├── charts/
    │   ├── 2026-03-01_firewall_blocks_chart.png
    │   └── ...
    └── exports/
        └── ...
```

### File Naming Convention

**Daily Reports:**
- Markdown: `YYYY-MM-DD_daily_report.md`
- HTML: `YYYY-MM-DD_daily_report.html`
- Metrics: `YYYY-MM-DD_metrics.json`

**Weekly Reports:**
- Markdown: `WNN_YYYY-MM-DD_to_YYYY-MM-DD_weekly_rollup.md`
- HTML: `WNN_YYYY-MM-DD_to_YYYY-MM-DD_weekly_rollup.html`
- Metrics: `WNN_YYYY-MM-DD_to_YYYY-MM-DD_metrics.json`

Where `WNN` is ISO week number (W01-W53).

### Data Storage Formats

#### 1. Markdown Reports (Human-Readable)
- Full narrative report as shown above
- Git-trackable (plain text)
- Easy to diff and review changes
- Can be rendered to HTML for email

#### 2. HTML Reports (Email-Ready)
- Rendered from Markdown with CSS styling
- Includes embedded charts (base64 encoded)
- Ready to send via email
- Archival copy for web viewing

#### 3. Metrics JSON (Machine-Readable)
```json
{
  "report_id": "uuid-here",
  "report_type": "daily",
  "date": "2026-03-04",
  "query_window": {
    "start": "2026-03-03T00:00:00Z",
    "end": "2026-03-04T00:00:00Z"
  },
  "metrics": {
    "security": {
      "firewall_blocks": {
        "count": 1832,
        "change_vs_avg": "+12%",
        "top_source_ip": "192.0.2.1",
        "top_target_port": 22
      },
      "dns_blocks": {
        "count": 247,
        "high_risk_count": 18,
        "top_domain": "malicious.example.com"
      },
      "flow_alerts": {
        "critical": 2,
        "warning": 8,
        "top_alert_type": "probing_attempt"
      },
      "ssh_failures": 87,
      "unique_attacker_ips": 34
    },
    "infrastructure": {
      "disk_usage_percent": 27.3,
      "disk_used_gb": 68.2,
      "disk_trend": "stable",
      "peak_bandwidth_mbps": 345,
      "interface_errors": 0,
      "service_uptime_days": 7.3
    },
    "validator": {
      "attestation_effectiveness_percent": 99.2,
      "balance_eth": 32.045,
      "balance_change_24h": "+0.002",
      "peer_count_consensus": 78,
      "peer_count_execution": 45,
      "sync_status": "synced"
    }
  },
  "events": {
    "security_events": [
      {
        "timestamp": "2026-03-04T14:32:00Z",
        "type": "ssh_failed_login_spike",
        "source_ip": "185.220.101.42",
        "target": "docker.mcducklabs.com:22",
        "action_taken": "blocked_by_crowdsec",
        "severity": "warning"
      }
    ],
    "infrastructure_events": [
      {
        "timestamp": "2026-03-04T06:12:00Z",
        "type": "container_restart",
        "service": "fl-snmp-exporter",
        "reason": "health_check_timeout",
        "severity": "info"
      }
    ]
  },
  "trends": {
    "firewall_blocks_7d_avg": 1634,
    "dns_blocks_7d_avg": 223,
    "disk_growth_gb_per_day": 6.2
  },
  "action_items": {
    "critical": [],
    "warning": [],
    "info": [
      "Review high bandwidth usage pattern on switch port 8"
    ]
  }
}
```

#### 4. SQLite Database (Trend Analysis)
Store time-series metrics for long-term trend analysis and AI querying.

**Schema:**
```sql
-- Daily metrics table
CREATE TABLE daily_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT UNIQUE NOT NULL,
    date DATE NOT NULL,
    firewall_blocks INTEGER,
    dns_blocks INTEGER,
    dns_high_risk_blocks INTEGER,
    flow_alerts_critical INTEGER,
    flow_alerts_warning INTEGER,
    ssh_failures INTEGER,
    unique_attacker_ips INTEGER,
    disk_usage_percent REAL,
    disk_used_gb REAL,
    peak_bandwidth_mbps REAL,
    interface_errors INTEGER,
    attestation_effectiveness REAL,
    validator_balance_eth REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_daily_date ON daily_metrics(date);

-- Weekly metrics table
CREATE TABLE weekly_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT UNIQUE NOT NULL,
    week_number INTEGER,
    year INTEGER,
    start_date DATE,
    end_date DATE,
    firewall_blocks_total INTEGER,
    dns_blocks_total INTEGER,
    new_threats_count INTEGER,
    recurring_threats_count INTEGER,
    critical_events INTEGER,
    service_uptime_percent REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_weekly_date ON weekly_metrics(start_date, end_date);

-- Security events table (for trend correlation)
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP,
    event_type TEXT,
    source_ip TEXT,
    target TEXT,
    action_taken TEXT,
    severity TEXT,
    report_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_events_type ON security_events(event_type);
CREATE INDEX idx_events_source ON security_events(source_ip);

-- Threat intelligence table (persistent attackers)
CREATE TABLE threat_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    total_attempts INTEGER,
    threat_type TEXT,
    geography TEXT,
    status TEXT, -- 'active', 'banned', 'monitored'
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_threat_ip ON threat_intelligence(ip_address);
CREATE INDEX idx_threat_status ON threat_intelligence(status);
```

### Retention Policy

| Data Type | Retention Period | Reason |
|-----------|------------------|--------|
| Daily Markdown Reports | 90 days | Human-readable history |
| Daily HTML Reports | 30 days | Email archives (if needed) |
| Daily Metrics JSON | 365 days | Detailed trend analysis |
| Weekly Markdown Reports | 365 days | Long-term narrative |
| Weekly HTML Reports | 365 days | Annual review |
| Weekly Metrics JSON | Indefinite | Compact, valuable |
| SQLite Metrics DB | Indefinite | Efficient storage, queryable |
| Threat Intel DB | Indefinite | Security memory |
| Chart Images | 90 days | Regenerate from data |

### AI Agent Query Interface

The AI agent should be able to query historical reports via:

**1. Natural Language Queries:**
- "How many firewall blocks did we have last Tuesday?"
- "Show me the trend in DNS blocks over the past month"
- "When was the last time we saw IP 192.0.2.1?"
- "What were the top 3 security events this week?"
- "Has disk usage increased compared to last week?"

**2. SQL Queries (via LangChain SQL tools):**
- Direct access to SQLite databases
- Complex trend analysis queries
- Cross-correlation of events

**3. File Access:**
- Read full Markdown reports for narrative context
- Parse JSON for structured data
- Generate comparison reports between date ranges

### Backup Strategy

**Daily Backup:**
```bash
# Backup reports and databases
rsync -avz /opt/first-light/reports/ /mnt/nas/backups/first-light-reports/

# Backup to S3 (optional, weekly)
aws s3 sync /opt/first-light/reports/ s3://homelab-reports/first-light/ \
  --exclude "*.html" \
  --exclude "attachments/charts/*"
```

**Git Integration:**
- Commit daily/weekly Markdown reports to Git (version control)
- Exclude HTML, JSON, and databases from Git (too large)
- Allows tracking report format evolution over time

---

## 4. Highest Value Metrics

Based on the available data sources and homelab security priorities, here are the **TOP 10 metrics** ranked by security value:

### Rank 1: Cross-VLAN Traffic (CRITICAL)
**What:** Unexpected traffic between isolated VLANs (especially Camera VLAN 3, Validator DMZ VLAN 4)
**Why:** Indicates misconfiguration, compromised device, or security policy violation
**Current Collection:** ✅ YES (pfSense filterlog extracts interface/VLAN)
**Query:**
```
resource.attributes["service.name"] = 'filterlog'
AND attributes["network.vlan"] = 'cameras'
AND attributes["pfsense.action"] = 'pass'
```
**Alert Threshold:** ANY traffic from Camera VLAN to other VLANs = CRITICAL
**Normal Pattern:** Camera VLAN should be 100% isolated (no outbound except NVR)

---

### Rank 2: Persistent/Returning Attackers
**What:** IPs that attempt access multiple times despite being blocked
**Why:** Indicates targeted attack vs automated scanning; suggests reconnaissance
**Current Collection:** ✅ YES (pfSense logs + CrowdSec integration possible)
**Query:**
```
COUNT(DISTINCT source_ip) WHERE blocked_attempts > 10 per day
GROUP BY source_ip
HAVING appearances_across_days > 3
```
**Alert Threshold:** Same IP blocked >50 times AND returns on 3+ different days = CRITICAL
**Normal Pattern:** Most scanners give up after first block

---

### Rank 3: High-Risk DNS Blocks (AdGuard)
**What:** DNS queries to known malware/C&C/phishing domains
**Why:** Indicates potentially compromised device or malware on network
**Current Collection:** ⚠️ PARTIAL (AdGuard API available, not yet integrated)
**Data Source:** AdGuard API `/control/stats` and `/control/querylog`
**Alert Threshold:** ANY high-risk block from Trusted VLAN device = CRITICAL
**Normal Pattern:** IoT devices may hit ad/tracker domains (low risk), Trusted VLAN should be clean

---

### Rank 4: Failed SSH Attempts (Brute Force Detection)
**What:** Failed SSH login attempts, especially clustered within short time
**Why:** Credential stuffing attack, may eventually succeed if weak passwords
**Current Collection:** ✅ YES (Docker host syslog, pfSense syslog)
**Query:**
```
body LIKE '%sshd%Failed%'
COUNT per source_ip
WHERE attempts > 5 in 5 minutes
```
**Alert Threshold:** >10 failures from same IP in 5 minutes = WARNING, >20 = CRITICAL
**Normal Pattern:** 0-2 failures per day from fat-finger mistakes

---

### Rank 5: Device Unreachable (SNMP Polling Failure)
**What:** Critical infrastructure (switch, firewall, NAS) stops responding to SNMP
**Why:** Device down, network path broken, or misconfiguration; data collection blind
**Current Collection:** ✅ YES (SNMP exporter metrics)
**Metric:** `snmp_uptime` (absence of data = unreachable)
**Alert Threshold:** No data for 5 minutes = CRITICAL
**Normal Pattern:** Continuous SNMP polling every 60 seconds

---

### Rank 6: ntopng Critical Flow Alerts
**What:** ntopng security alerts marked as "Error" or "Critical" severity
**Why:** Indicates malicious traffic patterns (probing, data exfiltration, etc.)
**Current Collection:** ✅ YES (ntopng syslog with severity extraction)
**Query:**
```
resource.attributes["host.name"] = 'ntopng'
AND (attributes["ntopng.severity"] = 'error' OR attributes["ntopng.severity"] = 'critical')
```
**Alert Threshold:** ANY critical ntopng alert = WARNING (investigate)
**Normal Pattern:** 0-2 per day (mostly false positives filtered)

---

### Rank 7: Interface Errors/Discards (Network Health)
**What:** Physical layer errors or buffer overruns on switch/firewall interfaces
**Why:** Indicates failing hardware, bad cable, or network congestion
**Current Collection:** ✅ YES (SNMP metrics)
**Metric:** `rate(interface_in_errors)` or `rate(interface_out_errors)`
**Alert Threshold:** >10 errors/sec for 5 minutes = WARNING, >100 = CRITICAL
**Normal Pattern:** 0 errors (or <1/sec on high-traffic interfaces)

---

### Rank 8: Disk Space Exhaustion (Storage Health)
**What:** Disk usage on observability stack, NAS, or Proxmox
**Why:** Prevents logging (blind to attacks), causes service crashes
**Current Collection:** ✅ YES (automated monitoring script + NAS SNMP)
**Metric:** Disk usage percent + growth rate
**Alert Threshold:** >75% = WARNING, >85% = CRITICAL
**Normal Pattern:** ~6 GB/day growth (7-day retention keeps at 25-30%)

---

### Rank 9: ETH Validator Missed Attestations
**What:** Validator failed to attest to beacon chain blocks
**Why:** Potential revenue loss, indicates downtime or sync issues
**Current Collection:** ⚠️ NO (Nimbus/Nethermind metrics not yet integrated)
**Data Source:** Nimbus beacon API `/eth/v1/validator/duties/attester/{epoch}`
**Metric:** `beacon_validator_attestations_missed_total`
**Alert Threshold:** >2 missed in 1 hour = WARNING, >5 = CRITICAL
**Normal Pattern:** 0 missed (>99% effectiveness target)

---

### Rank 10: Container/Service Restarts
**What:** Docker container restarted unexpectedly (not planned maintenance)
**Why:** Indicates instability, OOM kills, or health check failures
**Current Collection:** ✅ YES (Docker host syslog)
**Query:**
```
resource.attributes["host.name"] = 'docker'
AND attributes["docker.event_type"] = 'container_stop'
AND body NOT LIKE '%gracefully%'
```
**Alert Threshold:** >3 restarts of same service in 10 minutes = WARNING
**Normal Pattern:** 0 unplanned restarts (planned maintenance excluded)

---

### Summary Table

| Rank | Metric | Severity | Currently Collected | Implementation Gap |
|------|--------|----------|---------------------|-------------------|
| 1 | Cross-VLAN Traffic | CRITICAL | ✅ YES | Need query/alert |
| 2 | Persistent Attackers | CRITICAL | ✅ YES | Need aggregation logic |
| 3 | High-Risk DNS Blocks | CRITICAL | ⚠️ PARTIAL | AdGuard API integration |
| 4 | SSH Brute Force | WARNING | ✅ YES | Need query/alert |
| 5 | Device Unreachable | CRITICAL | ✅ YES | Need no-data alert |
| 6 | ntopng Critical Alerts | WARNING | ✅ YES | Need query/alert |
| 7 | Interface Errors | WARNING | ✅ YES | Need rate alert |
| 8 | Disk Space | CRITICAL | ✅ YES | Alert exists (monitor script) |
| 9 | Validator Missed Attestations | WARNING | ❌ NO | Need metric integration |
| 10 | Service Restarts | WARNING | ✅ YES | Need query/alert |

**Key Insight:** 8 out of 10 high-value metrics are already being collected. The primary gap is building the queries/alerts, not data collection.

---

## 5. Implementation Priority

### Phase 1: MVP Daily Report (Week 1)
**Goal:** Get a basic daily email with top security metrics

**Tasks:**
1. **Create Python script: `agent/reports/daily_threat_assessment.py`**
   - Query SigNoz API for past 24 hours
   - Extract key metrics (firewall blocks, DNS blocks, disk usage)
   - Generate Markdown report from template
   - Save to `/opt/first-light/reports/daily/`

2. **Implement basic queries:**
   - Firewall blocks: `service.name = 'filterlog' AND action = 'block'` (count)
   - Top blocked IP: `GROUP BY source_ip LIMIT 1`
   - Disk usage: Read from monitoring script log
   - Service health: Check container status via Docker API

3. **Email delivery:**
   - Render Markdown to HTML
   - Send via SMTP (or use existing webhook-relay to Telegram)
   - Subject line: `[First Light] Daily Threat Assessment - {date} - {status}`

4. **Cron job:**
   ```bash
   0 8 * * * cd /opt/first-light && python agent/reports/daily_threat_assessment.py
   ```

5. **Storage:**
   - Save Markdown: `/opt/first-light/reports/daily/{YYYY}/{MM}/{date}_daily_report.md`
   - Save metrics JSON: `{date}_metrics.json`

**Metrics to Include (MVP):**
- Firewall blocks (count, top source IP)
- Disk usage (percent, trend)
- Service uptime (all containers healthy?)
- Top 3 security events (if any)

**Success Criteria:**
- Daily email received by 08:00 every morning
- Readable in <2 minutes
- Accurate metrics (validated against SigNoz UI)

**Estimated Effort:** 6-8 hours

---

### Phase 2: Enhanced Daily Report (Week 2)
**Goal:** Add intelligence and context to daily reports

**Tasks:**
1. **Add trend analysis:**
   - Create SQLite database for metrics storage
   - Store daily metrics after each report
   - Compare today vs 7-day average
   - Show percent change (↑↓)

2. **Integrate AdGuard metrics:**
   - Build `agent/tools/adguard.py` (API client)
   - Query `/control/stats` for blocked domains
   - Parse `/control/querylog` for high-risk blocks
   - Add to daily report

3. **Parse ntopng alerts:**
   - Query SigNoz for `host.name = 'ntopng' AND severity >= WARN`
   - Extract alert types and counts
   - Highlight critical-severity alerts

4. **Cross-VLAN detection:**
   - Query for Camera VLAN traffic: `network.vlan = 'cameras' AND action = 'pass'`
   - Alert if ANY traffic detected (should be isolated)

5. **SSH brute force detection:**
   - Query: `body LIKE '%sshd%Failed%' | COUNT BY source_ip`
   - Flag IPs with >10 failures in 24h

6. **Action items generation:**
   - Rule-based: If disk >75%, add action item
   - Rule-based: If cross-VLAN traffic, add CRITICAL action
   - Rule-based: If >50 SSH failures from same IP, add action

**Metrics to Add:**
- DNS blocks (total, high-risk breakdown)
- ntopng alerts (by severity and type)
- Cross-VLAN traffic (should be ZERO)
- SSH failure spikes (by source IP)
- Trend indicators (vs 7-day avg)

**Success Criteria:**
- Daily report includes all Top 10 metrics (except validator)
- Trends show percent change
- Action items automatically generated when thresholds exceeded

**Estimated Effort:** 10-12 hours

---

### Phase 3: Weekly Rollup (Week 3)
**Goal:** Automated weekly summary with pattern analysis

**Tasks:**
1. **Create script: `agent/reports/weekly_rollup.py`**
   - Query past 7 days from SigNoz
   - Aggregate metrics (totals, averages, peaks)
   - Compare to previous week

2. **Persistent threat tracking:**
   - Create `threat_intelligence` SQLite table
   - Track IPs across days (first_seen, last_seen, total_attempts)
   - Identify "persistent attackers" (>3 days, >50 attempts)

3. **Pattern detection:**
   - Time-series analysis: Detect spikes (>2 stdev from mean)
   - Day-of-week patterns: Weekend vs weekday traffic
   - New vs recurring threats

4. **Week-over-week comparison:**
   - Query previous week's metrics from SQLite
   - Calculate percent change
   - Generate comparison table

5. **Recommendations engine:**
   - Rule-based: If disk projected full in <30 days, recommend action
   - Rule-based: If new persistent attacker, recommend IP ban review
   - Rule-based: If service restarts >5/week, recommend investigation

**Metrics to Include:**
- All daily metrics (aggregated)
- New threats this week (IPs/domains not seen before)
- Recurring threats (persistent bad actors)
- Week-over-week trends
- 4-week trend chart

**Success Criteria:**
- Weekly report generated every Sunday 20:00
- Identifies new vs recurring threats
- Compares to previous week
- Provides actionable recommendations

**Estimated Effort:** 12-15 hours

---

### Phase 4: Trend Analysis & AI Integration (Week 4+)
**Goal:** Enable AI agent to query historical data and identify long-term patterns

**Tasks:**
1. **Build LangChain SQL query tool:**
   - Tool: `query_metrics_db(sql_query: str) -> DataFrame`
   - Connect to SQLite databases
   - Allow AI agent to write SQL for complex queries

2. **Natural language query interface:**
   - Example: "Show me firewall blocks over the past month"
   - AI agent translates to SQL query
   - Results formatted in Markdown/charts

3. **Anomaly detection:**
   - Statistical: Z-score analysis (>2 stdev = anomaly)
   - Time-series: Detect sudden spikes or drops
   - Correlate anomalies across metrics (e.g., disk spike + log volume spike)

4. **Threat correlation:**
   - Cross-reference firewall blocks + DNS blocks from same IP
   - Identify multi-stage attacks (scanning → brute force → data exfil)
   - Generate narrative explanations

5. **Automated chart generation:**
   - Use matplotlib/plotly to generate trend charts
   - Embed in HTML reports (base64 encoded)
   - Save to `/opt/first-light/reports/attachments/charts/`

6. **Interactive Telegram queries:**
   - `/report today` - Generate daily report on demand
   - `/report week` - Generate weekly rollup
   - `/query "show me top attackers this week"` - Natural language SQL

**Success Criteria:**
- AI agent can answer questions about historical data
- Anomalies automatically detected and highlighted
- Threat correlation identifies multi-stage attacks
- Reports include embedded charts

**Estimated Effort:** 20-25 hours

---

## Summary Roadmap

| Phase | Deliverable | Effort | Depends On |
|-------|-------------|--------|------------|
| **Phase 1** | MVP Daily Report | 6-8 hrs | SigNoz API access |
| **Phase 2** | Enhanced Daily Report | 10-12 hrs | Phase 1, AdGuard API |
| **Phase 3** | Weekly Rollup | 12-15 hrs | Phase 2, SQLite DB |
| **Phase 4** | AI Trend Analysis | 20-25 hrs | Phase 3, LangGraph agent |

**Total Estimated Effort:** 48-60 hours (6-8 days of focused work)

---

## Technical Implementation Notes

### SigNoz API Queries
The AI agent needs to query SigNoz ClickHouse via the API. Reference: `/docs/SIGNOZ_API_GUIDE.md`

**Example Query (Firewall Blocks Count):**
```python
import httpx

def get_firewall_blocks_24h():
    query = {
        "start": int((datetime.now() - timedelta(days=1)).timestamp() * 1e9),
        "end": int(datetime.now().timestamp() * 1e9),
        "filters": {
            "items": [
                {"key": "service_name", "value": "filterlog", "op": "="},
                {"key": "pfsense_action", "value": "block", "op": "="}
            ]
        },
        "aggregateOperator": "count"
    }

    response = httpx.post(
        "http://localhost:8081/api/v3/query_range",
        json=query
    )
    return response.json()
```

### SQLite Schema Creation
```sql
-- Create tables on first run
CREATE TABLE IF NOT EXISTS daily_metrics (...);
CREATE TABLE IF NOT EXISTS threat_intelligence (...);
```

### Email Rendering
Use `markdown2` library to convert Markdown to HTML:
```python
import markdown2

html_body = markdown2.markdown(markdown_report, extras=["tables", "fenced-code-blocks"])
```

### Cron Job Setup
Add to `/etc/crontab` or user crontab:
```bash
# Daily report at 08:00
0 8 * * * cd /opt/first-light && /usr/bin/python3 agent/reports/daily_threat_assessment.py

# Weekly rollup on Sunday at 20:00
0 20 * * 0 cd /opt/first-light && /usr/bin/python3 agent/reports/weekly_rollup.py
```

---

## Questions for User

Before implementation, clarify:

1. **Email vs Telegram?**
   - Email: Requires SMTP config (Gmail, SendGrid, etc.)
   - Telegram: Use existing webhook-relay (simpler, already configured)
   - Recommendation: Start with Telegram, add email later

2. **Report Delivery Time?**
   - 08:00 local time suggested for daily report
   - Confirm timezone: America/Chicago (CST/CDT)

3. **Action Item Thresholds?**
   - Disk >75% = WARNING (suggested)
   - Firewall blocks >2000/day = WARNING?
   - SSH failures >50/day from same IP = WARNING?
   - Confirm or adjust

4. **Validator Metrics Priority?**
   - High priority: Integrate Nimbus/Nethermind metrics now?
   - Low priority: Defer to Phase 4?

5. **Git Backup of Reports?**
   - Commit daily/weekly Markdown to Git?
   - Pros: Version control, offsite backup
   - Cons: Repo size grows (~50 KB/day)

---

## Appendix: Example Queries

### Cross-VLAN Traffic Detection
```sql
-- SigNoz ClickHouse query
SELECT
    timestamp,
    attributes['pfsense.src_ip'] as source,
    attributes['pfsense.dst_ip'] as dest,
    attributes['network.vlan'] as vlan,
    attributes['pfsense.action'] as action
FROM signoz_logs.logs
WHERE
    resource_attributes['service.name'] = 'filterlog'
    AND attributes['network.vlan'] = 'cameras'
    AND attributes['pfsense.action'] = 'pass'
    AND timestamp >= now() - INTERVAL 24 HOUR
ORDER BY timestamp DESC
```

### Persistent Attackers (Week)
```sql
-- SQLite query on security_events table
SELECT
    source_ip,
    COUNT(*) as total_attempts,
    COUNT(DISTINCT DATE(timestamp)) as days_seen,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen
FROM security_events
WHERE
    event_type = 'firewall_block'
    AND timestamp >= datetime('now', '-7 days')
GROUP BY source_ip
HAVING days_seen >= 3 AND total_attempts >= 50
ORDER BY total_attempts DESC
```

### SSH Brute Force Detection
```sql
-- SigNoz ClickHouse query
SELECT
    attributes['source_ip'] as attacker,
    COUNT(*) as failed_attempts
FROM signoz_logs.logs
WHERE
    body LIKE '%sshd%Failed%'
    AND timestamp >= now() - INTERVAL 24 HOUR
GROUP BY attributes['source_ip']
HAVING failed_attempts >= 10
ORDER BY failed_attempts DESC
```

---

**End of Document**

*This plan provides a comprehensive framework for building actionable security intelligence from the First Light observability stack. Implementation should follow the phased approach, starting with MVP daily reports and progressively adding intelligence and automation.*
