"""
First Light Slack Bot (S3-03)

Uses Slack Bolt in Socket Mode — no public URL required. Listens for:
  - App mentions (@firstlight <question>)
  - /firstlight slash command with optional subcommands:
      /firstlight status
      /firstlight report
      /firstlight ask <question>

Conversation history per channel is stored in Redis (same structure as Telegram).

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
_HISTORY_TTL = 3600 * 4
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


def _history_key(channel: str) -> str:
    return f"slack:history:{channel}"


def _load_history(channel: str) -> list[dict]:
    r = _get_redis()
    if not r:
        return []
    try:
        raw = r.get(_history_key(channel))
        return json.loads(raw) if raw else []
    except Exception:
        return []


def _save_history(channel: str, history: list[dict]) -> None:
    r = _get_redis()
    if not r:
        return
    try:
        trimmed = history[-_HISTORY_MAX_TURNS:]
        r.setex(_history_key(channel), _HISTORY_TTL, json.dumps(trimmed))
    except Exception:
        pass


def _atomic_append_turns(channel: str, turns: list[dict], max_retries: int = 3) -> None:
    """Atomically append turns to Slack conversation history using WATCH/MULTI/EXEC."""
    r = _get_redis()
    if not r:
        return
    key = _history_key(channel)
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
                import random, time as _time
                _time.sleep(random.uniform(0.05, 0.15))
                continue
            try:
                r.setex(key, _HISTORY_TTL, json.dumps(turns[-_HISTORY_MAX_TURNS:]))
            except Exception:
                pass
            return


# ── Message chunking ─────────────────────────────────────────────────────────────

async def _post_chunks(say, text: str) -> None:
    """Post a potentially long response as multiple messages."""
    chunks = split_message(text, _MSG_CHUNK)
    for i, chunk in enumerate(chunks):
        suffix = f"\n_(continued {i+1}/{len(chunks)})_" if len(chunks) > 1 else ""
        await say(chunk + suffix)


# ── Query helper ─────────────────────────────────────────────────────────────────

async def _run_query(question: str, channel: str, session_prefix: str = "slack") -> str:
    """Run the interactive agent query with history. Returns answer text."""
    history = _load_history(channel)
    try:
        from agent.graph import run_interactive_query
        answer = await run_interactive_query(
            question=question,
            history=history,
            session_id=f"{session_prefix}-{channel}",
        )
        _atomic_append_turns(channel, [
            {"role": "user", "content": question},
            {"role": "assistant", "content": answer},
        ])
        return answer
    except Exception as e:
        logger.error("Slack query failed: %s", e, exc_info=True)
        return f":warning: Query failed: {e}"


# ── Handler functions (registered inside _main to avoid module-level AsyncApp) ──

async def handle_mention(event, say):
    """Handle @firstlight <question> mentions."""
    text = event.get("text", "")
    # Remove <@BOTID> prefix
    question = text.split(">", 1)[-1].strip() if ">" in text else text.strip()
    if not question:
        await say("Hi! Ask me anything about your network, or use `/firstlight help`.")
        return

    channel = event.get("channel", "unknown")
    await say(":hourglass_flowing_sand: Querying the network data...")
    answer = await _run_query(question, channel)
    await _post_chunks(say, answer)


async def handle_dm(event, say):
    """Handle direct messages to the bot."""
    # Ignore bot messages and message edits
    if event.get("bot_id") or event.get("subtype"):
        return
    text = (event.get("text") or "").strip()
    if not text:
        return

    channel = event.get("channel", "unknown")
    await say(":hourglass_flowing_sand: Querying the network data...")
    answer = await _run_query(question=text, channel=channel, session_prefix="slack-dm")
    await _post_chunks(say, answer)


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
            "`/firstlight ask <question>` — Ask anything about the network\n"
            "`/firstlight help` — Show this message\n\n"
            "_Or `@firstlight <question>` for a natural language query._"
        )
        return

    if text == "status":
        await say(":hourglass_flowing_sand: Running status check...")
        answer = await _run_query(
            "Give me a concise status summary covering: "
            "(1) QNAP NAS health, (2) Proxmox VMs, (3) recent firewall blocks, "
            "(4) top threat intel findings. Use bullet points. Be brief.",
            channel,
        )
        await _post_chunks(say, answer)
        return

    if text == "report":
        if not _can_acquire_report_lock():
            await say(":hourglass_flowing_sand: A report is already running — check back in a few minutes.")
            return
        await say(":hourglass_flowing_sand: Generating report... this may take a minute.")
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
        return

    # Strip "ask " prefix if present, otherwise treat entire text as question
    question = text[4:].strip() if text.startswith("ask ") else text

    if question:
        await say(":hourglass_flowing_sand: Querying the network data...")
        answer = await _run_query(question, channel)
        await _post_chunks(say, answer)
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

    # Import here so module-level import doesn't fail when slack-bolt is installed
    # but tokens are not yet configured (e.g., during test discovery)
    from slack_bolt.async_app import AsyncApp
    from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler

    app = AsyncApp(token=bot_token)
    app.event("app_mention")(handle_mention)
    app.event({"type": "message", "channel_type": "im"})(handle_dm)
    app.command("/firstlight")(handle_slash)

    logger.info("First Light Slack bot starting (Socket Mode)...")

    _MAX_BACKOFF = 300  # 5 minutes
    backoff = 5
    while True:
        try:
            handler = AsyncSocketModeHandler(app, app_token)
            await handler.start_async()
            # start_async() returned cleanly (shouldn't happen in normal op — treat as disconnect)
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
