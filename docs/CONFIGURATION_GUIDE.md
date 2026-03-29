# First Light — Configuration Guide

All configuration is via environment variables in `.env`. This guide covers every variable added or changed in Sprint 3.

---

## Notification Channels

### Telegram

| Variable | Required | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Yes (for Telegram) | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Yes (for Telegram) | Default chat to send scheduled reports to |
| `TELEGRAM_ALLOWED_CHAT_IDS` | No | Comma-separated list of chat IDs the bot will respond to. Defaults to `TELEGRAM_CHAT_ID` if not set. |

**Setup:**
1. Create a bot via @BotFather on Telegram → get `TELEGRAM_BOT_TOKEN`
2. Start a conversation with the bot or add it to a group, then get the chat ID:
   ```
   curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
   ```
3. Set `TELEGRAM_CHAT_ID` and `TELEGRAM_ALLOWED_CHAT_IDS`

### Slack

| Variable | Required | Description |
|---|---|---|
| `SLACK_WEBHOOK_URL` | For report delivery | Incoming webhook URL (outbound reports only) |
| `SLACK_BOT_TOKEN` | For interactive bot | `xoxb-...` OAuth bot token |
| `SLACK_APP_TOKEN` | For interactive bot | `xapp-...` app-level token (needs `connections:write` scope) |
| `SLACK_MSG_CHUNK` | No | Max chars per message chunk (default: 2800) |

**Setup (incoming webhook only — for report delivery):**
1. Go to your Slack app → Incoming Webhooks → Add New Webhook
2. Set `SLACK_WEBHOOK_URL`

**Setup (interactive bot — Socket Mode):**
1. Create a Slack app at api.slack.com/apps
2. Enable Socket Mode → generate an App-Level Token with `connections:write` → `SLACK_APP_TOKEN`
3. Add OAuth scopes: `chat:write`, `app_mentions:read`, `commands`
4. Create `/firstlight` slash command pointing to your app
5. Install to workspace → copy Bot User OAuth Token → `SLACK_BOT_TOKEN`
6. Enable the `app_mention` event subscription
7. Start the `fl-slack-bot` service (see Docker section below)

---

## Management UI

| Variable | Required | Description |
|---|---|---|
| `UI_BASIC_AUTH_USER` | No | Basic auth username (default: `admin`) |
| `UI_BASIC_AUTH_PASSWORD` | No | Basic auth password. Leave unset to disable auth. |

The UI runs on port **8085**. Access at `http://<host>:8085`.

Features:
- Dashboard with recent reports and integration status
- Reports browser with inline view and raw download
- On-demand report trigger (POST /api/report/trigger)
- System status (Redis, notification channels, integrations)

---

## Redis

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://fl-redis:6379/0` | Redis connection URL for conversation history and distributed locks |

---

## QNAP NAS

| Variable | Required | Description |
|---|---|---|
| `QNAP_API_URL` | No | QNAP base URL, e.g. `http://192.168.2.106:8080` |
| `QNAP_API_USER` | No | QNAP admin username |
| `QNAP_API_PASS` | No | QNAP admin password |

Used by `query_qnap_directory_sizes` tool for disk space analysis.

---

## Docker Services

### Starting the bots

The bot services use the `bots` Docker Compose profile so they don't start by default with `docker compose up`:

```bash
# Start everything including bots
docker compose --profile bots up -d

# Or start individual services (use service names, not container names)
docker compose up -d telegram-bot
docker compose up -d slack-bot
docker compose up -d ui
```

### Service summary

| Service | Container | Port | Profile |
|---|---|---|---|
| Agent scheduler | `fl-agent` | — | default |
| Telegram bot | `fl-telegram-bot` | — | bots |
| Slack bot | `fl-slack-bot` | — | bots |
| Management UI | `fl-ui` | 8085 | default |

### Checking bot logs

```bash
# Telegram bot
docker logs -f fl-telegram-bot

# Slack bot
docker logs -f fl-slack-bot

# Management UI
docker logs -f fl-ui
```

---

## Scheduler Environment

| Variable | Default | Description |
|---|---|---|
| `DAILY_REPORT_HOUR` | `8` | Hour (24h) for daily report |
| `DAILY_REPORT_MINUTE` | `0` | Minute for daily report |
| `TZ` | `America/Chicago` | Timezone for scheduler |
| `RUN_ON_STARTUP` | `false` | Set to `true` to run a report immediately on container start |

---

## Example `.env` additions (Sprint 3)

```dotenv
# Telegram
TELEGRAM_BOT_TOKEN=1234567890:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TELEGRAM_CHAT_ID=-1001234567890
TELEGRAM_ALLOWED_CHAT_IDS=-1001234567890,9876543210

# Slack (webhook only)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx

# Slack (interactive bot — both required)
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...

# Management UI
UI_BASIC_AUTH_PASSWORD=changeme

# QNAP
QNAP_API_URL=http://192.168.2.106:8080
QNAP_API_USER=admin
QNAP_API_PASS=your-qnap-password

# Redis (default works if using fl-redis container)
REDIS_URL=redis://fl-redis:6379/0
```
