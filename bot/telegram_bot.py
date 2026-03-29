"""
First Light Telegram Bot (S3-02)

Commands:
  /start   — welcome message
  /help    — list commands
  /status  — quick infrastructure health check
  /report  — trigger a full daily report now
  /ask <q> — ask the AI agent a specific question

Any free-text message (without a command prefix) is routed to the AI agent
as a natural language query with conversation history preserved in Redis.

Security: only responds to chat IDs listed in TELEGRAM_ALLOWED_CHAT_IDS
(comma-separated). Falls back to TELEGRAM_CHAT_ID if not set.
"""

import asyncio
import json
import logging
import os
import signal
from typing import Optional

from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from agent.utils.text import split_message

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("telegram_bot")

_HISTORY_TTL = 3600 * 4   # 4-hour conversation window
_HISTORY_MAX_TURNS = 20   # cap stored turns
_MSG_CHUNK = 4000          # Telegram safe chunk size

# Module-level Redis singleton — avoids a new connection per message
_redis_client = None


def _get_allowed_ids() -> set[str]:
    """Return set of allowed Telegram chat ID strings from config."""
    from agent.config import get_config
    cfg = get_config()
    # telegram_allowed_chat_ids: comma-separated list of chat IDs
    allowed = cfg.telegram_allowed_chat_ids or ""
    if not allowed:
        # Fall back to the single chat ID used for report delivery
        allowed = cfg.telegram_chat_id or ""
    return {cid.strip() for cid in allowed.split(",") if cid.strip()}


def _is_allowed(update: Update) -> bool:
    allowed = _get_allowed_ids()
    if not allowed:
        # No allow-list configured — deny all to avoid accidental exposure
        logger.warning(
            "TELEGRAM_ALLOWED_CHAT_IDS not configured — rejecting message from chat %s",
            update.effective_chat.id,
        )
        return False
    return str(update.effective_chat.id) in allowed


def _get_redis():
    """Return the Redis singleton client, creating it on first call."""
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


def _history_key(chat_id: int) -> str:
    return f"bot:history:{chat_id}"


def _load_history(chat_id: int) -> list[dict]:
    r = _get_redis()
    if not r:
        return []
    try:
        raw = r.get(_history_key(chat_id))
        return json.loads(raw) if raw else []
    except Exception:
        return []


def _save_history(chat_id: int, history: list[dict]) -> None:
    r = _get_redis()
    if not r:
        return
    try:
        trimmed = history[-_HISTORY_MAX_TURNS:]
        r.setex(_history_key(chat_id), _HISTORY_TTL, json.dumps(trimmed))
    except Exception:
        pass


def _atomic_append_turns(chat_id: int, turns: list[dict], max_retries: int = 3) -> None:
    """Atomically append one or more turns to conversation history.

    Uses Redis WATCH + MULTI/EXEC optimistic locking so concurrent messages from
    the same chat don't clobber each other. Falls back to unconditional write
    after max_retries exhausted (same behaviour as before, but rare).
    """
    r = _get_redis()
    if not r:
        return
    key = _history_key(chat_id)
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
            return  # success
        except Exception as e:
            import redis as _redis
            if isinstance(e, _redis.WatchError) and attempt < max_retries:
                import random, time as _time
                _time.sleep(random.uniform(0.05, 0.15))
                continue
            # WatchError exhausted or other error — unconditional write
            try:
                r.setex(key, _HISTORY_TTL, json.dumps(turns[-_HISTORY_MAX_TURNS:]))
            except Exception:
                pass
            return


async def _send_chunks(update: Update, text: str) -> None:
    """Send a long message as multiple chunks."""
    for chunk in split_message(text, _MSG_CHUNK):
        await update.message.reply_text(chunk, parse_mode=ParseMode.MARKDOWN)


# ── Command handlers ────────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return
    await update.message.reply_text(
        "👋 *First Light AI* is online.\n\n"
        "I monitor your network security and infrastructure.\n"
        "Use /help to see available commands.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return
    await update.message.reply_text(
        "*First Light AI — Commands*\n\n"
        "/status — Quick infrastructure health check\n"
        "/report — Generate a full daily report now\n"
        "/ask <question> — Ask anything about the network\n"
        "/help — Show this message\n\n"
        "_Or just type any question naturally._",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        from agent.graph import run_interactive_query
        answer = await run_interactive_query(
            question=(
                "Give me a concise status summary covering: "
                "(1) QNAP NAS health, (2) Proxmox VMs, (3) recent firewall blocks, "
                "(4) top threat intel findings. Use bullet points. Be brief."
            ),
            session_id=f"tg-{update.effective_chat.id}",
        )
        await _send_chunks(update, answer)
    except Exception as e:
        logger.error("Status command failed: %s", e, exc_info=True)
        await update.message.reply_text(f"⚠️ Status check failed: {e}")


def _can_acquire_report_lock() -> bool:
    """Try to acquire the shared report lock. Returns True if acquired, False if already held."""
    from agent.scheduler import REPORT_LOCK_KEY, REPORT_LOCK_TTL
    r = _get_redis()
    if not r:
        return True  # Redis unavailable — proceed without lock
    try:
        acquired = r.set(REPORT_LOCK_KEY, "bot-triggered", nx=True, ex=REPORT_LOCK_TTL)
        return bool(acquired)
    except Exception:
        return True  # best-effort


def _release_report_lock() -> None:
    from agent.scheduler import REPORT_LOCK_KEY
    r = _get_redis()
    if r:
        try:
            r.delete(REPORT_LOCK_KEY)
        except Exception:
            pass


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return

    if not _can_acquire_report_lock():
        await update.message.reply_text(
            "⏳ A report is already running — check back in a few minutes."
        )
        return

    await update.message.reply_text("⏳ Generating report... this may take a minute.")
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        from agent.reports.daily_threat_assessment import generate_daily_report
        from agent.notifications import broadcast_report, register_defaults
        from agent.notifications.registry import get_channels
        if not get_channels():
            await register_defaults()
        report = await generate_daily_report()
        await broadcast_report(report)
        await update.message.reply_text(f"✅ Report generated: `{report['date']}`", parse_mode="Markdown")
    except Exception as e:
        logger.error("On-demand report failed: %s", e, exc_info=True)
        await update.message.reply_text(f"⚠️ Report failed: {e}")
    finally:
        _release_report_lock()


async def cmd_ask(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return
    question = " ".join(context.args) if context.args else ""
    if not question:
        await update.message.reply_text("Usage: /ask <your question>")
        return
    await _handle_query(update, question)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Route free-text messages to the AI agent."""
    if not _is_allowed(update):
        return
    if not update.message or not update.message.text:
        return
    await _handle_query(update, update.message.text)


async def _handle_query(update: Update, question: str) -> None:
    """Run an interactive query with conversation history and send the response."""
    chat_id = update.effective_chat.id
    await update.message.chat.send_action(ChatAction.TYPING)

    # Load history snapshot for context (read-only — write happens atomically after)
    history = _load_history(chat_id)

    try:
        from agent.graph import run_interactive_query
        answer = await run_interactive_query(
            question=question,
            history=history,
            session_id=f"tg-{chat_id}",
        )

        # Atomically append both turns — handles concurrent messages from same chat
        _atomic_append_turns(chat_id, [
            {"role": "user", "content": question},
            {"role": "assistant", "content": answer},
        ])

        await _send_chunks(update, answer)

    except Exception as e:
        logger.error("Query failed: %s", e, exc_info=True)
        await update.message.reply_text(f"⚠️ Something went wrong: {e}")


# ── Entry point ──────────────────────────────────────────────────────────────────

def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN is not set")

    app = (
        Application.builder()
        .token(token)
        .build()
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("ask", cmd_ask))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("First Light Telegram bot starting (polling)...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
