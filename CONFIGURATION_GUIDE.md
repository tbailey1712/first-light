# First Light Configuration Guide

This guide covers advanced configuration options for your First Light observability stack.

## 📊 Table of Contents

1. [SNMP Device Configuration](#snmp-device-configuration)
2. [SigNoz Saved Views](#signoz-saved-views)
3. [Alert Rules](#alert-rules)
4. [Data Retention Policies](#data-retention-policies)
5. [CrowdSec Bouncer Setup](#crowdsec-bouncer-setup)
6. [GeoIP Enrichment](#geoip-enrichment)

---

## SNMP Device Configuration

### Adding SNMP-Monitored Devices

Edit `signoz/otel-collector-config.yaml` and add your device IPs to the SNMP scrape config:

```yaml
- job_name: snmp
  static_configs:
    - targets:
      - 192.168.1.10  # Main switch (with description)
      - 192.168.1.20  # Access point
      - 192.168.1.30  # Secondary switch
```

### Enabling SNMP on Devices

**For UniFi Switches:**
1. Log into UniFi Controller
2. Navigate to: Settings → Services → SNMP
3. Enable SNMPv2c
4. Set community string to `public` (or custom, update snmp.yml)

**For Ubiquiti EdgeSwitch:**
1. SSH to switch or use web UI
2. Enable SNMP: `configure` → `snmp-server community public`
3. Save config

**For pfSense (optional):**
1. Navigate to: Services → SNMP
2. Enable SNMP Daemon
3. Read Community String: `public`
4. Save

### Custom SNMP Community String

If using a custom community string (recommended for security):

1. Edit `snmp-exporter/snmp.yml`:
```yaml
auths:
  custom_v2:
    community: your_custom_string_here
```

2. Update the scrape config to use the new auth

---

## SigNoz Saved Views

Create these saved queries in SigNoz for quick access to common views.

### Security Events View

**Query:**
```
pfsense.action = "block" OR severity_number >= SEVERITY_NUMBER_WARN
```

**Description:** All blocked traffic and warnings/errors across all devices

**Group By:** `host.name`, `pfsense.dst_port`

---

### SSH Attempts View

**Query:**
```
pfsense.dst_port = "22" OR body contains "sshd" OR body contains "Failed password"
```

**Description:** All SSH-related activity (connections, attempts, failures)

**Group By:** `pfsense.src_ip`, `severity_text`

---

### External Traffic View

**Query:**
```
pfsense.direction = "in" AND NOT (
  pfsense.src_ip startsWith "192.168" OR
  pfsense.src_ip startsWith "10." OR
  pfsense.src_ip startsWith "172.16"
)
```

**Description:** All inbound traffic from public IPs

**Group By:** `pfsense.src_ip`, `pfsense.dst_port`, `pfsense.action`

---

### Error Logs Only

**Query:**
```
severity_number >= SEVERITY_NUMBER_ERROR
```

**Description:** Errors across all systems

**Group By:** `host.name`, `service.name`

---

### Per-Device Breakdown

Create separate views for each device type:

**Firewall Logs:**
```
device.type = "firewall"
```

**Hypervisor Logs:**
```
device.type = "hypervisor"
```

**NAS Logs:**
```
device.type = "nas"
```

---

### High-Volume Traffic

**Query:**
```
pfsense.action = "pass" AND pfsense.direction = "out"
```

**Description:** Outbound allowed traffic (bandwidth analysis)

**Group By:** `pfsense.src_ip`, `pfsense.dst_ip`

---

## Alert Rules

Configure alerts in SigNoz UI: **Alerts → New Alert**

### Critical: Multiple SSH Failures

**Query:**
```
body contains "Failed password" AND service.name = "sshd"
```

**Condition:** Count > 5 in 5 minutes

**Severity:** Critical

**Notification:** Telegram/Email

---

### Critical: Firewall Blocking Spike

**Query:**
```
pfsense.action = "block"
```

**Condition:** Count > 100 in 1 minute

**Severity:** Critical

**Description:** Possible port scan or DoS attempt

---

### Warning: Disk Space

**Query:**
```
body contains "disk" AND (body contains "full" OR body contains "low")
```

**Condition:** Any match

**Severity:** Warning

---

### Warning: Service Restart

**Query:**
```
body contains "restart" OR body contains "starting" OR body contains "stopped"
```

**Condition:** Count > 3 in 10 minutes (same service)

**Severity:** Warning

**Description:** Service instability

---

### Info: New Device on Network

**Query:**
```
body contains "DHCP" AND body contains "new"
```

**Condition:** Any match

**Severity:** Info

**Description:** Track new devices connecting to network

---

## Data Retention Policies

### Current Settings

- **Logs:** Default retention (until disk full)
- **Metrics:** Default retention
- **Compression:** ZSTD level 3 enabled

### Configuring Retention via SigNoz UI

1. Navigate to: **Settings → Retention**
2. Set retention periods:
   - **Logs:** 90 days (recommended for home use)
   - **Traces:** 30 days
   - **Metrics:** 180 days

### Manual Retention via ClickHouse

For advanced users, you can set TTL on specific tables:

```sql
-- Connect to ClickHouse
docker exec -it signoz-clickhouse clickhouse-client

-- Set 90-day TTL on logs
ALTER TABLE signoz_logs.logs MODIFY TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- Set 180-day TTL on metrics
ALTER TABLE signoz_metrics.samples MODIFY TTL toDateTime(timestamp) + INTERVAL 180 DAY;
```

### Storage Monitoring

Monitor disk usage:
```bash
# Check Docker volume sizes
docker system df -v | grep signoz

# Check ClickHouse data size
docker exec signoz-clickhouse clickhouse-client --query "
  SELECT
    table,
    formatReadableSize(sum(bytes)) as size
  FROM system.parts
  WHERE active
  GROUP BY table
  ORDER BY sum(bytes) DESC
"
```

---

## CrowdSec Bouncer Setup

Bouncers enforce blocking decisions from CrowdSec. For pfSense:

### Install pfSense Bouncer

1. **In pfSense:**
   - Install package: **System → Package Manager → Available Packages**
   - Search for "CrowdSec"
   - Click Install (if available), or use FreeBSD pkg:
   ```bash
   pkg install crowdsec-firewall-bouncer
   ```

2. **Generate API Key on Docker host:**
   ```bash
   sudo docker exec fl-crowdsec cscli bouncers add pfsense-bouncer
   ```
   Copy the API key shown.

3. **Configure Bouncer on pfSense:**
   Edit `/usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`:
   ```yaml
   api_url: http://192.168.2.106:8080
   api_key: <paste-api-key-here>
   ```

4. **Start Bouncer:**
   ```bash
   service crowdsec_firewall start
   ```

5. **Verify:**
   ```bash
   # On Docker host, check bouncer is connected
   sudo docker exec fl-crowdsec cscli bouncers list
   ```

### Test Blocking

Trigger a detection (simulate SSH brute force) and verify the IP gets blocked on pfSense.

---

## GeoIP Enrichment

CrowdSec already has GeoIP enrichment enabled. To add it to OTel collector for all logs:

### Option 1: Use CrowdSec's GeoIP

CrowdSec is already enriching IPs with geo data. You can query this via CrowdSec API.

### Option 2: Add GeoIP to OTel Collector

Requires a GeoIP database (MaxMind GeoLite2). Not included by default due to licensing.

**Steps (if you have a MaxMind license):**

1. Download GeoLite2-City.mmdb
2. Add to docker-compose volume mount
3. Add geoip processor to otel-collector-config.yaml

---

## Performance Tuning

### High-Volume Environments

If you're ingesting >10K logs/sec or >100K metrics/min:

**OTel Collector:**
```yaml
processors:
  batch:
    send_batch_size: 50000      # Increase batch size
    send_batch_max_size: 100000
    timeout: 5s                  # Reduce timeout
```

**ClickHouse:**
```yaml
environment:
  - CLICKHOUSE_MAX_MEMORY_USAGE: 8000000000  # 8GB
  - CLICKHOUSE_MAX_CONCURRENT_QUERIES: 100
```

### Low-Resource Environments

If running on limited hardware (<8GB RAM):

**Reduce batch sizes:**
```yaml
processors:
  batch:
    send_batch_size: 1000
    timeout: 30s
```

**Enable log sampling:**
Already configured! Adjust filter rules in `transform/device_context` to drop more if needed.

---

## Network Topology Documentation

Update your network topology as devices are added. This helps the AI agent (future phase) understand your network.

Create `network_topology.yaml`:
```yaml
network:
  vlans:
    - id: 1
      name: Management
      subnet: 192.168.1.0/24
      devices: [firewall, switch, controller]
    - id: 2
      name: Trusted
      subnet: 192.168.2.0/24
      devices: [servers, desktops]
    - id: 3
      name: IoT
      subnet: 192.168.3.0/24
      devices: [cameras, sensors, smart-home]
    - id: 4
      name: Guest
      subnet: 192.168.4.0/24
      devices: [guest-clients]

devices:
  firewall:
    hostname: firewall.mcducklabs.com
    type: pfSense
    role: edge-router
    interfaces:
      - mvneta0.1: management
      - mvneta0.2: trusted
      - mvneta0.3: iot
      - mvneta0.4: guest
      - mvneta2: wan

  pve:
    hostname: pve.mcducklabs.com
    type: Proxmox VE
    role: hypervisor
    vms:
      - name: docker
        ip: 192.168.2.106
        role: observability-stack
```

This will be used by the AI agent (NetOps AI) in future phases.

---

## Next Steps

1. ✅ Pull latest config: `cd /opt/first-light && sudo git pull`
2. ✅ Restart stack: `sudo docker compose up -d`
3. 📋 Add SNMP device IPs to otel-collector-config.yaml
4. 📊 Create saved views in SigNoz UI
5. 🚨 Configure alert rules
6. 🛡️ Set up CrowdSec bouncer (optional, for active blocking)
7. 📈 Monitor storage and adjust retention as needed

---

## Support

- **SigNoz Docs:** https://signoz.io/docs/
- **CrowdSec Docs:** https://docs.crowdsec.net/
- **OTel Collector:** https://opentelemetry.io/docs/collector/
- **pfSense + CrowdSec:** https://docs.crowdsec.net/docs/bouncers/firewall/

---

**Your observability stack is now fully configured! 🎉**
