# Issue #2: Notification Channel Setup

## Objective
Configure SigNoz alerting to send notifications to Telegram via webhook-relay.

## Status
- ✅ webhook-relay service exists (`/webhook-relay/app.py`)
- ✅ Telegram credentials configured in `.env`
- ✅ Service running and tested
- ✅ SigNoz alert channel configured

## Architecture
```
SigNoz Alert Manager → webhook-relay (port 5001) → Telegram Bot API → User
```

## Steps

### 1. Verify webhook-relay is running
On the server (192.168.2.106):
```bash
cd /opt/first-light
sudo docker compose ps | grep webhook-relay
```

If not running:
```bash
sudo docker compose up -d webhook-relay
```

### 2. Test webhook-relay health
```bash
curl http://192.168.2.106:5001/health
```
Expected: `{"status": "healthy"}`

### 3. Test Telegram delivery
Send a test webhook:
```bash
curl -X POST http://192.168.2.106:5001/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "status": "firing",
    "alerts": [{
      "status": "firing",
      "labels": {
        "alertname": "Test Alert",
        "severity": "info"
      },
      "annotations": {
        "description": "This is a test alert from First Light"
      },
      "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
    }]
  }'
```

Expected: Message appears in Telegram

### 4. Configure SigNoz Alert Channel
In SigNoz UI (http://192.168.2.106:3000 or 8081):

1. Go to **Settings** → **Alert Channels** (or **Notification Channels**)
2. Click **"Add Channel"** or **"New Channel"**
3. Configure:
   - **Type**: Webhook (or Alertmanager Webhook)
   - **Name**: `Telegram via webhook-relay`
   - **Webhook URL**: `http://webhook-relay:5000/webhook`
   - **Method**: POST
   - **Headers** (if needed): `Content-Type: application/json`
4. **Test** the channel (should send to Telegram)
5. **Save**

Note: Use `webhook-relay:5000` (internal Docker network) not `192.168.2.106:5001` (external).

### 5. Create a Test Alert
Create a simple alert to verify the full pipeline:

**Alert Name**: High Interface Errors
**Condition**: `interface_in_errors` rate > 0 for 1 minute
**Severity**: Warning
**Notification Channel**: Telegram via webhook-relay
**Message Template**:
```
Interface errors detected on {{device}}
Interface: {{name}}
Error rate: {{value}} errors/sec
```

### 6. Trigger the Alert
Generate some test errors (optional) or wait for natural errors.

Alternatively, create a simpler "always-firing" test alert:
**Condition**: `interface_in_octets` rate > 0 for 1 minute
This will fire immediately since there's always traffic.

## Verification Checklist

- [ ] webhook-relay container is running
- [ ] Health endpoint responds
- [ ] Test webhook delivers to Telegram
- [ ] SigNoz alert channel configured
- [ ] Test alert created
- [ ] Alert fires and appears in Telegram
- [ ] Alert message is readable and useful

## Expected Alert Format in Telegram

```
🔥 High Interface Errors
Status: FIRING
Severity: 🟡 warning

Interface errors detected on switch.mcducklabs.com
Interface: port 15: Gigabit Copper
Error rate: 12.5 errors/sec

Labels: device=switch.mcducklabs.com, name=port 15: Gigabit Copper
Started: 2026-03-02 18:45:32 UTC
```

## Troubleshooting

### webhook-relay not responding
```bash
sudo docker compose logs webhook-relay --tail=50
```
Check for:
- Missing environment variables
- Python errors
- Port conflicts

### Alert not firing
- Check alert condition is actually met
- Verify metric data exists in ClickHouse
- Check SigNoz alert manager logs

### Alert fires but no Telegram message
- Check webhook-relay logs
- Verify Telegram bot token is valid
- Verify chat ID is correct
- Test Telegram API directly:
  ```bash
  curl "https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>&text=Test"
  ```

## Next Steps
After notification channel is working:
- Create production alerts (Issue #3)
- Document alert runbook
- Set up alert routing (critical vs warning vs info)
