# AdGuard DNS Analytics → SigNoz Metrics Exporter

Exports AdGuard DNS analytics from SQLite to SigNoz as OpenTelemetry metrics.

## What It Exports

### Client Metrics (per client_ip)
- `adguard.queries.total` - Total DNS queries (24h)
- `adguard.blocks.total` - Total blocked queries (24h)
- `adguard.block.rate` - Block percentage
- `adguard.client.risk_score` - Risk score (0-10)

**Labels**: `client.ip`, `client.name`, `traffic.type`

### Security Metrics
- `adguard.anomalies.detected` - Count by type and severity

**Labels**: `anomaly.type`, `severity`

### Domain Metrics
- `adguard.blocked_domains.total` - Top 20 blocked domains

**Labels**: `domain`, `unique_clients`

### Pipeline Health
- `adguard.ingestion.duration` - Ingestion run time
- `adguard.ingestion.records` - Records processed/skipped

**Labels**: `status`, `type`

## Installation

### On AdGuard LXC (adguard.mcducklabs.com)

```bash
# 1. Copy files to AdGuard server
scp adguard_metrics_exporter.py root@adguard:/home/tbailey/adgh/
scp requirements.txt root@adguard:/home/tbailey/adgh/

# 2. SSH to AdGuard
ssh root@adguard

# 3. Install dependencies
cd /home/tbailey/adgh
python3 -m pip install -r requirements.txt

# 4. Make executable
chmod +x adguard_metrics_exporter.py

# 5. Test run
./adguard_metrics_exporter.py
```

Expected output:
```
2026-03-03 20:00:00 - AdGuardMetricsExporter - INFO - Connected to database: /home/tbailey/adgh/cache.db
2026-03-03 20:00:01 - AdGuardMetricsExporter - INFO - Exported metrics for 45 clients
2026-03-03 20:00:01 - AdGuardMetricsExporter - INFO - Exported 12 anomaly metric groups
2026-03-03 20:00:01 - AdGuardMetricsExporter - INFO - Exported top 20 blocked domains
2026-03-03 20:00:01 - AdGuardMetricsExporter - INFO - Exported ingestion health: completed
2026-03-03 20:00:03 - AdGuardMetricsExporter - INFO - Export completed successfully in 3.12 seconds
```

## Scheduling

### Option 1: Cron (Recommended)

Run hourly at 5 minutes past the hour (after ingestion completes):

```bash
# Edit crontab
crontab -e

# Add this line:
5 * * * * /home/tbailey/adgh/adguard_metrics_exporter.py >> /var/log/adguard-metrics-export.log 2>&1
```

### Option 2: Systemd Timer

Create `/etc/systemd/system/adguard-metrics-export.service`:
```ini
[Unit]
Description=AdGuard Metrics Export to SigNoz
After=network.target

[Service]
Type=oneshot
User=tbailey
WorkingDirectory=/home/tbailey/adgh
ExecStart=/usr/bin/python3 /home/tbailey/adgh/adguard_metrics_exporter.py
StandardOutput=journal
StandardError=journal
```

Create `/etc/systemd/system/adguard-metrics-export.timer`:
```ini
[Unit]
Description=Run AdGuard metrics export hourly

[Timer]
OnCalendar=*:05:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:
```bash
systemctl daemon-reload
systemctl enable --now adguard-metrics-export.timer
systemctl list-timers | grep adguard
```

## Verification

### Check SigNoz for Metrics

1. Open SigNoz: http://192.168.2.106:8081
2. Go to **Metrics Explorer**
3. Search for: `adguard`
4. You should see:
   - `adguard.queries.total`
   - `adguard.blocks.total`
   - `adguard.block.rate`
   - `adguard.client.risk_score`
   - `adguard.anomalies.detected`
   - `adguard.blocked_domains.total`

### Example Queries

**Total queries by client:**
```
adguard.queries.total{client.ip="192.168.1.100"}
```

**Block rate for automated clients:**
```
adguard.block.rate{traffic.type="automated"}
```

**High-risk clients:**
```
adguard.client.risk_score > 5
```

**Anomalies by severity:**
```
sum(adguard.anomalies.detected) by (severity)
```

**Top blocked domain:**
```
topk(10, adguard.blocked_domains.total)
```

## Troubleshooting

### No metrics in SigNoz

1. **Check exporter ran:**
   ```bash
   tail -f /var/log/adguard-metrics-export.log
   ```

2. **Test connectivity to SigNoz:**
   ```bash
   nc -zv 192.168.2.106 4317
   ```

3. **Check SigNoz OTel collector logs:**
   ```bash
   # On docker host (192.168.2.106)
   sudo docker compose logs otel-collector --tail=50 | grep adguard
   ```

4. **Verify database path:**
   ```bash
   ls -lh /home/tbailey/adgh/cache.db
   sqlite3 /home/tbailey/adgh/cache.db "SELECT COUNT(*) FROM client_summary"
   ```

### Import errors

If you get `ModuleNotFoundError`:
```bash
python3 -m pip install --upgrade opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc
```

### Database locked

If you get "database is locked" error, the ingestion is still running. Wait 1-2 minutes and retry.

## Configuration

Edit `adguard_metrics_exporter.py` to change:

```python
DB_PATH = "/home/tbailey/adgh/cache.db"  # SQLite database path
SIGNOZ_ENDPOINT = "192.168.2.106:4317"    # SigNoz OTel collector
EXPORT_INTERVAL_MS = 60000                # Export frequency during run
```

## Logs

Exporter logs go to:
- Cron: `/var/log/adguard-metrics-export.log`
- Systemd: `journalctl -u adguard-metrics-export.service`

## Next Steps

Once metrics are flowing to SigNoz:

1. **Create dashboards** showing:
   - DNS query volume by client
   - Block rates over time
   - Risk score trends
   - Top blocked domains
   - Anomaly detection timeline

2. **Set up alerts** for:
   - High risk score clients (> 7)
   - Anomaly spikes (severity=high)
   - Block rate changes (sudden increase)
   - Ingestion failures

3. **Correlate with network metrics** (SNMP, pfSense):
   - High DNS blocks + high firewall blocks = compromised device?
   - DNS anomaly + unusual network traffic = investigation needed
