# Webhook Relay — SigNoz to Telegram

Simple Flask service that translates SigNoz Alertmanager-format webhooks into Telegram messages.

## How It Works

1. **SigNoz** sends webhook alerts in Prometheus Alertmanager JSON format
2. **Webhook Relay** receives the webhook, extracts alert data, formats it nicely
3. **Telegram Bot API** delivers the formatted message to your Telegram chat

## Configuration

Set in `.env` file:
- `TELEGRAM_BOT_TOKEN` - Bot token from @BotFather
- `TELEGRAM_CHAT_ID` - Your chat ID (from @userinfobot)

## Endpoints

- `POST /webhook` - Receives SigNoz alerts (configure this in SigNoz notification channel)
- `GET /health` - Health check endpoint

## SigNoz Configuration

In SigNoz UI:
1. Go to **Settings → Alert Channels**
2. Click **New Channel**
3. Configure:
   - **Name:** Telegram - Tony
   - **Type:** Webhook
   - **Webhook URL:** `http://webhook-relay:5000/webhook`
   - **Send Resolved:** ✅ On

## Message Format

Alerts are formatted with:
- 🔥 Firing / ✅ Resolved status
- Alert name and severity (🔴 critical, 🟡 warning, 🔵 info)
- Description/summary from annotations
- Relevant labels
- Timestamp

## Example Alert

```
🔥 *HighCPU*
*Status:* FIRING
*Severity:* 🔴 critical

CPU usage above 90% on host pve

*Labels:* `host=pve, instance=192.168.2.5:9100`
*Started:* 2026-02-26 16:30:00 UTC
```
