# SigNoz Critical Alerts Setup

These alert rules provide immediate notification of critical security and infrastructure events.

## Alert Rules Created

1. **cross-vlan-breach.yaml** - CRITICAL security alert for isolated VLAN traffic
2. **disk-space-critical.yaml** - Disk >90% full alert
3. **ssh-brute-force.yaml** - SSH brute force detection (>5 attempts in 5 min)
4. **validator-offline.yaml** - ETH validator offline/missed attestations

## Installation

### Method 1: SigNoz UI (Recommended)

1. **Access SigNoz**
   ```
   http://192.168.2.106:8081/alerts
   ```

2. **Create Each Alert**

   For each `.yaml` file:

   a. Click **"New Alert"**

   b. **Configure Query:**
   - Select query type (Logs or Metrics)
   - Add filters from the YAML file
   - Set group by fields

   c. **Set Condition:**
   - Copy the condition logic from YAML
   - Set threshold value
   - Set evaluation window

   d. **Add Alert Details:**
   - Alert name
   - Severity label
   - Description (from annotations)

   e. **Configure Notifications:**
   - Select notification channel (email, Telegram, etc.)
   - Set severity

### Method 2: SigNoz API

**Note:** SigNoz alert API endpoint (if available):

```bash
# Example - adjust based on SigNoz API documentation
curl -X POST http://192.168.2.106:8081/api/v1/rules \
  -H "Content-Type: application/json" \
  -d @cross-vlan-breach.json
```

### Method 3: Convert to SigNoz Format

Use the YAML files as reference to create alerts via UI with these settings:

#### Cross-VLAN Breach Alert

**Query Type:** Logs

**Filters:**
```
resources_string['service.name'] = 'filterlog'
AND (
  attributes_string['pfsense.interface'] IN ('mvneta0.3', 'mvneta0.4')
  OR attributes_string['network.vlan'] IN ('camera', 'validator')
)
AND attributes_string['pfsense.direction'] = 'out'
```

**Condition:** count() > 0
**Eval Window:** 1 minute
**Severity:** CRITICAL

---

#### Disk Space Critical Alert

**Query Type:** Metrics

**Metric:** `disk_used_percent` (or equivalent from your SNMP exporter)

**Group By:** host.name, mount_point

**Condition:** max(disk_used_percent) > 90
**Eval Window:** 5 minutes
**Severity:** CRITICAL

---

#### SSH Brute Force Alert

**Query Type:** Logs

**Filters:**
```
resources_string['service.name'] = 'sshd'
AND body CONTAINS 'Failed password'
```

**Group By:** attributes_string['ssh.source_ip']
(or extract from body if SSH parser not working)

**Condition:** count() > 5
**Eval Window:** 5 minutes
**Severity:** WARNING

---

#### Validator Offline Alert

**Query Type:** Metrics

**Option A - Missing Metrics:**
```
Metric: validator_balance (or any core metric)
Condition: count() == 0 over 10 minutes
```

**Option B - Missed Attestations:**
```
Metric: validator_attestations_missed_total
Condition: rate(5m) > 0
```

**Eval Window:** 10 minutes
**Severity:** CRITICAL

## Notification Setup

Before alerts work, configure notification channels:

### Email Notification

**SigNoz Settings → Notification Channels → Add Email**

- SMTP Server: your-smtp-server.com
- Port: 587 (TLS) or 465 (SSL)
- Username: alerts@mcducklabs.com
- Password: <your-smtp-password>
- From: First Light Alerts <alerts@mcducklabs.com>
- To: admin@mcducklabs.com

### Telegram Notification

**SigNoz Settings → Notification Channels → Add Webhook**

Use Telegram Bot API:
- Webhook URL: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/sendMessage`
- Method: POST
- Headers: `Content-Type: application/json`
- Body template:
  ```json
  {
    "chat_id": "<YOUR_CHAT_ID>",
    "text": "🚨 {{ .AlertName }}\n\n{{ .Description }}",
    "parse_mode": "Markdown"
  }
  ```

## Testing Alerts

### Test Cross-VLAN Breach

**Simulate by creating test log:**

```bash
# This would require actual traffic from Camera VLAN
# DO NOT test in production - could indicate real breach!
```

**Instead, verify by:**
1. Check filter matches existing logs (if any)
2. Review alert query results in SigNoz Logs Explorer

### Test Disk Space Alert

**Check current disk usage:**

```bash
ssh docker.mcducklabs.com "df -h"
```

If >90%, alert should trigger within 5 minutes.

**Simulate (carefully):**
```bash
# Create large file to push disk usage >90%
dd if=/dev/zero of=/tmp/testfile bs=1G count=50
```

**Clean up:**
```bash
rm /tmp/testfile
```

### Test SSH Brute Force

**Trigger by failing SSH login 6 times:**

```bash
# From remote machine
for i in {1..6}; do
  ssh wronguser@docker.mcducklabs.com  # Enter wrong password
  sleep 5
done
```

Alert should trigger after 5th attempt.

### Test Validator Offline

**Stop validator service temporarily:**

```bash
ssh vldtr.mcducklabs.com "sudo systemctl stop lighthouse-validator"
```

Alert should trigger after 10 minutes of no metrics.

**Restart immediately:**
```bash
ssh vldtr.mcducklabs.com "sudo systemctl start lighthouse-validator"
```

## Monitoring Alerts

### View Active Alerts

```
http://192.168.2.106:8081/alerts
```

### Alert History

Check notification channel logs:
- Email: Check inbox for "First Light Alerts"
- Telegram: Check bot messages

### Silence Alerts (During Maintenance)

In SigNoz UI:
1. Go to Alerts
2. Find active alert
3. Click "Silence"
4. Set duration (1h, 4h, 24h)
5. Add reason: "Scheduled maintenance"

## Troubleshooting

**Alerts not firing:**
1. Verify query returns results in Logs/Metrics Explorer
2. Check threshold values are correct
3. Verify notification channel is configured
4. Check SigNoz logs: `docker logs signoz --tail=100 | grep alert`

**Too many false positives:**
- Adjust threshold (e.g., SSH: 5→10 attempts)
- Increase eval window (e.g., 5m→15m)
- Add more filters to reduce noise

**Missing notifications:**
- Test notification channel separately
- Check spam folder for emails
- Verify Telegram bot token and chat ID
- Check notification channel logs in SigNoz

## Next Steps

After configuring these critical alerts:

1. **Monitor for 24-48 hours** - Tune thresholds if needed
2. **Add more alerts** - Based on threat assessment plan
3. **Create alert runbooks** - Document response procedures
4. **Set up on-call rotation** - Who responds to critical alerts?
5. **Integrate with incident management** - PagerDuty, Opsgenie, etc.

## Security Impact

**Before:** Manual log review, hours to detect threats
**After:** Real-time alerting, <5 minute detection

These 4 alerts cover the most critical security and infrastructure risks for your homelab.
