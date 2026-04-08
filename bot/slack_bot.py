"""
First Light Slack Bot (SLK-1 — SLK-4)

Uses Slack Bolt in Socket Mode — no public URL required. Listens for:
  - App mentions (@firstlight <question>) — replies in-thread (SLK-2)
  - Direct messages to the bot
  - /firstlight slash command with subcommands:
      /firstlight status
      /firstlight report
      /firstlight weekly
      /firstlight ask <question>
      /firstlight help
  - Interactive button actions on alert messages (SLK-2):
      alert_investigate  — run an investigation query in-thread
      alert_acknowledge  — mark alert as acknowledged (removes buttons)
      alert_snooze       — snooze the alert for 4h (removes buttons)

Conversation history per thread (or channel for DMs) is stored in Redis
keyed by thread_ts when available, otherwise by channel (SLK-4).
TTL: 24h. Max turns: 20.

Required env vars:
  SLACK_BOT_TOKEN   — xoxb-... (OAuth bot token)
  SLACK_APP_TOKEN   — xapp-... (app-level token with connections:write scope)

Optional:
  SLACK_MSG_CHUNK   — max chars per message part (default 2800)
"""

import asyncio
import json
import logging
import os

from agent.utils.text import split_message

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("slack_bot")

_MSG_CHUNK = int(os.getenv("SLACK_MSG_CHUNK", "2800"))
_HISTORY_TTL = 3600 * 24   # SLK-4: 24h
_HISTORY_MAX_TURNS = 20

# Module-level Redis singleton — avoids a new connection per message
_redis_client = None


# ── Redis helpers ────────────────────────────────────────────────────────────────

def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        import redis
        url = os.getenv("REDIS_URL", "redis://fl-redis:6379/0")
        _redis_client = redis.Redis.from_url(
            url, socket_connect_timeout=2, socket_timeout=2, decode_responses=True
        )
        _redis_client.ping()
        return _redis_client
    except Exception:
        return None


def _history_key(channel: str, thread_ts: str | None = None) -> str:
    """SLK-4: key by thread_ts when in a thread, otherwise by channel (DMs)."""
    if thread_ts:
        return f"slack:history:thread:{thread_ts}"
    return f"slack:history:{channel}"


def _load_history(channel: str, thread_ts: str | None = None) -> list[dict]:
    r = _get_redis()
    if not r:
        return []
    try:
        raw = r.get(_history_key(channel, thread_ts))
        return json.loads(raw) if raw else []
    except Exception:
        return []


def _atomic_append_turns(
    channel: str,
    turns: list[dict],
    thread_ts: str | None = None,
    max_retries: int = 3,
) -> None:
    """Atomically append turns to conversation history using WATCH/MULTI/EXEC."""
    r = _get_redis()
    if not r:
        return
    key = _history_key(channel, thread_ts)
    for attempt in range(max_retries + 1):
        try:
            with r.pipeline() as pipe:
                pipe.watch(key)
                raw = pipe.get(key)
                history = json.loads(raw) if raw else []
                history.extend(turns)
                trimmed = history[-_HISTORY_MAX_TURNS:]
                pipe.multi()
                pipe.setex(key, _HISTORY_TTL, json.dumps(trimmed))
                pipe.execute()
            return
        except Exception as e:
            import redis as _redis
            if isinstance(e, _redis.WatchError) and attempt < max_retries:
                import random
                import time as _time
                _time.sleep(random.uniform(0.05, 0.15))
                continue
            try:
                r.setex(key, _HISTORY_TTL, json.dumps(turns[-_HISTORY_MAX_TURNS:]))
            except Exception:
                pass
            return


# ── Message chunking ─────────────────────────────────────────────────────────────

async def _post_chunks(say, text: str, thread_ts: str | None = None) -> None:
    """Post a potentially long response as multiple messages."""
    chunks = split_message(text, _MSG_CHUNK)
    for i, chunk in enumerate(chunks):
        suffix = f"\n_(continued {i+1}/{len(chunks)})_" if len(chunks) > 1 else ""
        if thread_ts:
            await say(chunk + suffix, thread_ts=thread_ts)
        else:
            await say(chunk + suffix)


# ── Query helper ─────────────────────────────────────────────────────────────────

async def _run_query(
    question: str,
    channel: str,
    session_prefix: str = "slack",
    thread_ts: str | None = None,
) -> str:
    """Run the interactive agent query with thread-keyed history. Returns answer text."""
    history = _load_history(channel, thread_ts)
    try:
        from agent.graph import run_interactive_query
        answer = await run_interactive_query(
            question=question,
            history=history,
            session_id=f"{session_prefix}-{thread_ts or channel}",
        )
        _atomic_append_turns(channel, [
            {"role": "user", "content": question},
            {"role": "assistant", "content": answer},
        ], thread_ts=thread_ts)
        return answer
    except Exception as e:
        logger.error("Slack query failed: %s", e, exc_info=True)
        return f":warning: Query failed: {e}"


# ── Event handlers ───────────────────────────────────────────────────────────────

async def handle_mention(event, say):
    """Handle @firstlight <question> mentions — reply in-thread (SLK-2)."""
    text = event.get("text", "")
    # Remove <@BOTID> prefix
    question = text.split(">", 1)[-1].strip() if ">" in text else text.strip()
    if not question:
        thread_ts = event.get("ts")
        await say("Hi! Ask me anything about your network, or use `/firstlight help`.", thread_ts=thread_ts)
        return

    channel = event.get("channel", "unknown")
    # SLK-2: reply in the same thread as the mention
    thread_ts = event.get("thread_ts") or event.get("ts")
    await say(":hourglass_flowing_sand: Querying the network data...", thread_ts=thread_ts)
    answer = await _run_query(question, channel, thread_ts=thread_ts)
    await _post_chunks(say, answer, thread_ts=thread_ts)


_GREETINGS = {"hi", "hey", "hello", "yo", "sup", "howdy"}


async def handle_dm(event, say):
    """Handle direct messages to the bot."""
    if event.get("bot_id") or event.get("subtype"):
        return
    text = (event.get("text") or "").strip()
    if not text:
        return

    if text.lower().rstrip("!,.?") in _GREETINGS:
        await say("Hey! Ask me anything about your network — threats, infrastructure, validator status, you name it.")
        return

    channel = event.get("channel", "unknown")
    await say(":hourglass_flowing_sand: Querying the network data...")
    answer = await _run_query(question=text, channel=channel, session_prefix="slack-dm")
    await _post_chunks(say, answer)


# ── Interactive button handlers (SLK-2) ──────────────────────────────────────────

async def handle_investigate_action(ack, body, say, client):
    """Investigate button on an alert — run a targeted query and reply in-thread."""
    await ack()
    question = body["actions"][0]["value"]
    channel = body["channel"]["id"]
    message_ts = body["message"]["ts"]

    await say(
        f":mag: *Investigating:* _{question[:120]}_",
        thread_ts=message_ts,
    )
    answer = await _run_query(
        question=question,
        channel=channel,
        session_prefix="slack-investigate",
        thread_ts=message_ts,
    )
    await _post_chunks(say, answer, thread_ts=message_ts)


async def handle_acknowledge_action(ack, body, client):
    """Acknowledge button — removes action buttons and appends an acknowledgement note."""
    await ack()
    channel = body["channel"]["id"]
    message_ts = body["message"]["ts"]
    user_id = body["user"]["id"]

    original_blocks = body["message"].get("blocks", [])
    updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
    updated_blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f":white_check_mark: Acknowledged by <@{user_id}>"}],
    })
    try:
        await client.chat_update(
            channel=channel,
            ts=message_ts,
            blocks=updated_blocks,
            text="Alert acknowledged",
        )
    except Exception as e:
        logger.error("Failed to acknowledge alert message: %s", e)


async def handle_snooze_action(ack, body, client):
    """Snooze button — stores snooze state in Redis, removes action buttons."""
    await ack()
    channel = body["channel"]["id"]
    message_ts = body["message"]["ts"]
    user_id = body["user"]["id"]
    minutes = int(body["actions"][0]["value"] or "240")
    hours = minutes // 60

    # Store snooze so downstream alert senders can check before re-alerting
    r = _get_redis()
    if r:
        try:
            r.setex(f"slack:snooze:{channel}:{message_ts}", minutes * 60, user_id)
        except Exception:
            pass

    original_blocks = body["message"].get("blocks", [])
    updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
    updated_blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f":zzz: Snoozed {hours}h by <@{user_id}>"}],
    })
    try:
        await client.chat_update(
            channel=channel,
            ts=message_ts,
            blocks=updated_blocks,
            text=f"Alert snoozed {hours}h",
        )
    except Exception as e:
        logger.error("Failed to snooze alert message: %s", e)


# ── Slash command handler ─────────────────────────────────────────────────────────

def _can_acquire_report_lock() -> bool:
    """Try to acquire the shared report lock. Returns True if acquired, False if already held."""
    from agent.scheduler import REPORT_LOCK_KEY, REPORT_LOCK_TTL
    r = _get_redis()
    if not r:
        return True
    try:
        acquired = r.set(REPORT_LOCK_KEY, "slack-bot-triggered", nx=True, ex=REPORT_LOCK_TTL)
        return bool(acquired)
    except Exception:
        return True


def _release_report_lock() -> None:
    from agent.scheduler import REPORT_LOCK_KEY
    r = _get_redis()
    if r:
        try:
            r.delete(REPORT_LOCK_KEY)
        except Exception:
            pass


async def handle_slash(ack, body, say):
    """Handle /firstlight slash command."""
    await ack()

    text = (body.get("text") or "").strip()
    channel = body.get("channel_id", "unknown")

    if not text or text == "help":
        await say(
            "*First Light AI — Commands*\n\n"
            "`/firstlight status` — Quick infrastructure health check\n"
            "`/firstlight report` — Generate a full daily report now\n"
            "`/firstlight weekly` — Weekly trend summary: recurring issues and overdue actions\n"
            "`/firstlight ask <question>` — Ask anything about the network\n"
            "`/firstlight help` — Show this message\n\n"
            "_Or `@firstlight <question>` for a natural language query._"
        )
        return

    if text == "status":
        await say(":hourglass_flowing_sand: Running status check...")

        async def _run_status():
            answer = await _run_query(
                "Give me a concise status summary covering: "
                "(1) QNAP NAS health, (2) Proxmox VMs, (3) recent firewall blocks, "
                "(4) top threat intel findings. Use bullet points. Be brief.",
                channel,
            )
            await _post_chunks(say, answer)

        asyncio.ensure_future(_run_status())
        return

    if text == "weekly":
        await say(":hourglass_flowing_sand: Generating weekly trend summary... this takes about a minute.")

        async def _run_weekly():
            try:
                from agent.reports.weekly_summary import generate_weekly_summary_async
                from agent.notifications import broadcast_report, register_defaults
                from agent.notifications.registry import get_channels
                if not get_channels():
                    await register_defaults()
                report = await generate_weekly_summary_async()
                await broadcast_report(report)
                await say(
                    f":white_check_mark: Weekly summary complete: "
                    f"`{report['date_range']}` ({report['days_analyzed']} days analysed)"
                )
            except Exception as e:
                logger.error("Weekly summary failed: %s", e, exc_info=True)
                await say(f":warning: Weekly summary failed: {e}")

        asyncio.ensure_future(_run_weekly())
        return

    if text == "report":
        if not _can_acquire_report_lock():
            await say(":hourglass_flowing_sand: A report is already running — check back in a few minutes.")
            return
        await say(":hourglass_flowing_sand: Generating report... this may take a minute.")

        async def _run_report():
            try:
                from agent.reports.daily_threat_assessment import generate_daily_report
                from agent.notifications import broadcast_report, register_defaults
                from agent.notifications.registry import get_channels
                if not get_channels():
                    await register_defaults()
                report = await generate_daily_report()
                await broadcast_report(report)
                await say(f":white_check_mark: Report generated: `{report['date']}`")
            except Exception as e:
                logger.error("On-demand report failed: %s", e, exc_info=True)
                await say(f":warning: Report failed: {e}")
            finally:
                _release_report_lock()

        asyncio.ensure_future(_run_report())
        return

    # Strip "ask " prefix if present, otherwise treat entire text as question
    question = text[4:].strip() if text.startswith("ask ") else text

    if question:
        await say(":hourglass_flowing_sand: Querying the network data...")

        async def _run_ask():
            answer = await _run_query(question, channel)
            await _post_chunks(say, answer)

        asyncio.ensure_future(_run_ask())
    else:
        await say("Please provide a question. Usage: `/firstlight ask <your question>`")


# ── Entry point ──────────────────────────────────────────────────────────────────

async def _main():
    app_token = os.getenv("SLACK_APP_TOKEN")
    bot_token = os.getenv("SLACK_BOT_TOKEN")

    if not app_token:
        raise ValueError("SLACK_APP_TOKEN is not set (needs xapp-... token with connections:write scope)")
    if not bot_token:
        raise ValueError("SLACK_BOT_TOKEN is not set")

    from slack_bolt.async_app import AsyncApp
    from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler

    app = AsyncApp(token=bot_token)

    # Event handlers
    app.event("app_mention")(handle_mention)
    app.event({"type": "message", "channel_type": "im"})(handle_dm)

    # Slash command
    app.command("/firstlight")(handle_slash)

    # Interactive button actions (SLK-2)
    app.action("alert_investigate")(handle_investigate_action)
    app.action("alert_acknowledge")(handle_acknowledge_action)
    app.action("alert_snooze")(handle_snooze_action)

    logger.info("First Light Slack bot starting (Socket Mode)...")

    _MAX_BACKOFF = 300  # 5 minutes
    backoff = 5
    while True:
        try:
            handler = AsyncSocketModeHandler(app, app_token)
            await handler.start_async()
            backoff = 5
        except asyncio.CancelledError:
            logger.info("Slack bot shutting down (CancelledError)")
            break
        except Exception as e:
            logger.error("Slack Socket Mode disconnected: %s — reconnecting in %ss", e, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF)


def main():
    asyncio.run(_main())


if __name__ == "__main__":
    main()
