# Daily Threat Assessment Report - Setup Guide

## Overview

The daily threat assessment report automatically analyzes your network security posture every 24 hours using the First Light AI agent.

## What's Included

✅ **Automated Analysis** - AI agent queries all data sources (pfSense, ntopng, AdGuard, UniFi, Docker, HA)  
✅ **Comprehensive Report** - Executive summary, metrics, notable events, action items, trends  
✅ **Historical Storage** - Reports saved to `/opt/first-light/reports/daily/YYYY/MM/`  
✅ **Metrics Database** - SQLite database for trend analysis  
✅ **Configurable Schedule** - Default: 08:00 daily (via cron)  

## Installation

### 1. Deploy to Production Server

On your Docker host (docker.mcducklabs.com):

```bash
# Create reports directory
sudo mkdir -p /opt/first-light/reports/{daily,weekly,metrics}
sudo chown -R $USER:$USER /opt/first-light/reports

# Set environment variable for production
echo "export FIRST_LIGHT_REPORTS_DIR=/opt/first-light/reports" >> ~/.bashrc
source ~/.bashrc
```

### 2. Install Dependencies

```bash
cd /opt/first-light  # Or wherever you cloned the repo
pip install -r requirements.txt
```

### 3. Verify Configuration

Ensure `.env` has the LiteLLM credentials:

```bash
cat .env | grep LITELLM
```

Should show:
```
LITELLM_BASE_URL=https://model-router.mcducklabs.com
LITELLM_API_KEY=sk-...
LITELLM_MODEL=claude-sonnet-4-5
```

### 4. Test Report Generation

Run manually to verify:

```bash
cd /opt/first-light
python -m agent.reports.daily_threat_assessment
```

Check for output:
```
✅ Report saved: /opt/first-light/reports/daily/YYYY/MM/YYYY-MM-DD_daily_report.md
```

### 5. Schedule Daily Execution

Add to crontab:

```bash
crontab -e
```

Add this line (runs daily at 08:00 local time):

```cron
# First Light Daily Threat Assessment
0 8 * * * cd /opt/first-light && /usr/bin/python3 -m agent.reports.daily_threat_assessment >> /var/log/first-light-daily.log 2>&1
```

**Or** if you want to run it from a specific Python environment:

```cron
0 8 * * * cd /opt/first-light && /home/tbailey/miniconda3/bin/python -m agent.reports.daily_threat_assessment >> /var/log/first-light-daily.log 2>&1
```

### 6. View Logs

```bash
tail -f /var/log/first-light-daily.log
```

## Report Location

Reports are organized by date:

```
/opt/first-light/reports/
├── daily/
│   └── 2026/
│       └── 03/
│           ├── 2026-03-04_daily_report.md
│           ├── 2026-03-04_metrics.json
│           ├── 2026-03-05_daily_report.md
│           └── 2026-03-05_metrics.json
└── metrics/
    └── reports.db  (SQLite database)
```

## View Reports

### Via SSH

```bash
ssh docker.mcducklabs.com
cat /opt/first-light/reports/daily/$(date +%Y/%m/%Y-%m-%d)_daily_report.md
```

### Via Web (optional - future enhancement)

Set up a simple nginx static file server:

```nginx
location /reports/ {
    alias /opt/first-light/reports/;
    autoindex on;
    auth_basic "First Light Reports";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

## Notification Setup (Future Phase)

The report generator currently saves reports to disk. To send via Telegram:

1. Uncomment notification code in `daily_threat_assessment.py`
2. Ensure `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are in `.env`
3. Test with: `python -m agent.reports.daily_threat_assessment`

## Metrics Database

The SQLite database stores historical metrics for trend analysis:

```bash
sqlite3 /opt/first-light/reports/metrics/reports.db

# View recent metrics
SELECT date, firewall_blocks, dns_blocks FROM daily_metrics ORDER BY date DESC LIMIT 7;

# Get 7-day average
SELECT AVG(firewall_blocks) FROM daily_metrics WHERE date >= date('now', '-7 days');
```

## Troubleshooting

### Report Not Generated

1. Check cron is running: `systemctl status cron`
2. Check logs: `tail -f /var/log/first-light-daily.log`
3. Verify Python path: `which python3`
4. Test manually: `python -m agent.reports.daily_threat_assessment`

### Permission Errors

```bash
sudo chown -R $USER:$USER /opt/first-light/reports
```

### LiteLLM Connection Errors

Check API key is valid:
```bash
curl -H "Authorization: Bearer $LITELLM_API_KEY" https://model-router.mcducklabs.com/v1/models
```

### Database Lock Errors

If SQLite database is locked:
```bash
fuser /opt/first-light/reports/metrics/reports.db
# Kill any stuck processes
```

## Customization

### Change Report Time

Edit crontab and change `0 8` to desired hour (24h format):

```cron
0 6 * * *  # 06:00 daily
0 20 * * * # 20:00 daily
```

### Change Analysis Window

Edit `daily_threat_assessment.py`:

```python
# Change from 24 hours to 12 hours
query_security_summary(hours=12)
```

### Add Custom Metrics

Edit the analysis_prompt in `daily_threat_assessment.py` to add custom sections.

## Next Steps

- [ ] Set up Telegram notifications
- [ ] Add email delivery option
- [ ] Create weekly rollup report
- [ ] Add custom dashboards linking to Grafana
- [ ] Implement automated actions (ban persistent IPs, etc.)

---

**Current Status:** ✅ MVP Complete - Daily reports generating successfully!
