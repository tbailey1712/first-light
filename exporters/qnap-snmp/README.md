# QNAP NAS SNMP Exporter

Prometheus exporter for QNAP NAS that collects system metrics via SNMP.

## Features

**System Metrics:**
- CPU usage (percentage)
- System temperature
- Memory usage/total
- System uptime

**Disk Metrics:**
- Individual disk temperatures
- Disk health status (1=good, 0=error)
- Per-disk monitoring

**Volume Metrics:**
- Volume size/used/free space (bytes)
- Supports multiple volumes/pools

**Network Metrics:**
- Interface RX/TX bytes (counters)
- Per-interface statistics

## Setup

### 1. Enable SNMP on QNAP

In QNAP web UI:
1. Go to **Control Panel** → **Network & File Services** → **SNMP**
2. Enable **SNMP service**
3. Set SNMP version to **SNMPv2c**
4. Set Community name (default: `public`)
5. Apply settings

### 2. Test SNMP Access

From a machine with `snmpwalk` installed:
```bash
snmpwalk -v2c -c public nas.mcducklabs.com system
```

Should return QNAP system information.

### 3. Deploy Exporter

```bash
cd /opt/first-light/exporters/qnap-snmp
docker compose up -d
```

### 4. Verify

```bash
# Check logs
docker logs fl-qnap-snmp-exporter

# Test metrics endpoint
curl http://localhost:9003/metrics
```

## Metrics Format

```prometheus
# System metrics
qnap_cpu_usage_percent{host="nas.mcducklabs.com"} 50.7
qnap_system_temp_celsius{host="nas.mcducklabs.com"} 42
qnap_uptime_seconds{host="nas.mcducklabs.com"} 2028806

# Disk metrics
qnap_disk_temp_celsius{disk="HDD1",host="nas.mcducklabs.com"} 45
qnap_disk_status{disk="HDD1",host="nas.mcducklabs.com"} 1

# Volume metrics
qnap_volume_size_bytes{host="nas.mcducklabs.com",volume="DataVol1"} 1.099511627776e+13
qnap_volume_used_bytes{host="nas.mcducklabs.com",volume="DataVol1"} 5.49755813888e+12
qnap_volume_free_bytes{host="nas.mcducklabs.com",volume="DataVol1"} 5.49755813888e+12

# Network metrics
qnap_interface_rx_bytes_total{host="nas.mcducklabs.com",interface="eth0"} 2.603994777e+09
qnap_interface_tx_bytes_total{host="nas.mcducklabs.com",interface="eth0"} 2.612252136e+09
```

## Integration with OTel Collector

The exporter runs on port `9003`. Add to OTel collector scrape config:

```yaml
prometheus:
  config:
    scrape_configs:
      - job_name: qnap-nas
        static_configs:
          - targets: ['fl-qnap-snmp-exporter:9003']
        scrape_interval: 60s
```

## Troubleshooting

**No response from SNMP:**
- Check SNMP is enabled on QNAP
- Verify community string matches
- Check firewall allows SNMP (UDP 161)
- Test with `snmpwalk` from docker host

**Missing metrics:**
- Some OIDs may vary by QNAP model/firmware
- Check logs for SNMP errors
- Verify QNAP firmware is up to date

**High CPU on NAS:**
- Increase scrape interval (default: 60s)
- SNMP queries are lightweight but frequent polling can add load

## Configuration

Environment variables:
- `QNAP_HOST` - NAS hostname or IP (default: nas.mcducklabs.com)
- `SNMP_COMMUNITY` - SNMP community string (default: public)
- `SNMP_PORT` - SNMP port (default: 161)
- `EXPORTER_PORT` - Metrics port (default: 9003)
- `SCRAPE_INTERVAL` - Collection interval in seconds (default: 60)
