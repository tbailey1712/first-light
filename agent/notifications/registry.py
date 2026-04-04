"""
Notification channel registry.

Holds the list of active channels and provides broadcast_report() /
broadcast_alert() that fan-out to all registered channels concurrently.

Typical startup:
    from agent.notifications import register_defaults
    await register_defaults()
"""

import asyncio
import logging
from typing import Union

from agent.notifications.base import NotificationChannel
from agent.notifications.telegram import TelegramChannel, build_telegram_channel
from agent.notifications.slack import SlackWebhookChannel, build_slack_channel
from agent.notifications.ntfy import NtfyChannel, build_ntfy_channel

logger = logging.getLogger(__name__)

_channels: list[Union[TelegramChannel, SlackWebhookChannel, NtfyChannel]] = []


def register_channel(channel: Union[TelegramChannel, SlackWebhookChannel, NtfyChannel]) -> None:
    """Register a channel. Idempotent: won't add the same name twice."""
    for existing in _channels:
        if existing.name == channel.name:
            logger.debug("Channel '%s' already registered — skipping", channel.name)
            return
    _channels.append(channel)
    logger.info("Notification channel registered: %s", channel.name)


def get_channels() -> list:
    """Return current list of registered channels (read-only copy)."""
    return list(_channels)


async def register_defaults() -> None:
    """
    Auto-register channels based on available env vars and NOTIFICATION_CHANNELS config.
    Call once at application startup.

    NOTIFICATION_CHANNELS (env var): comma-separated list of channels to enable.
    Valid values: "slack", "telegram". Omit to enable all configured channels.
    """
    from agent.config import get_config
    cfg = get_config()

    # Build the allow-set from config; empty means "all"
    enabled: set[str] = set()
    if cfg.notification_channels:
        enabled = {c.strip().lower() for c in cfg.notification_channels.split(",") if c.strip()}

    def _want(name: str) -> bool:
        return not enabled or name in enabled

    if _want("telegram"):
        telegram = build_telegram_channel()
        if telegram:
            register_channel(telegram)
        else:
            logger.info("Telegram not configured (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing)")

    if _want("slack"):
        slack = build_slack_channel()
        if slack:
            register_channel(slack)
        else:
            logger.debug("Slack webhook not configured (SLACK_WEBHOOK_URL missing)")

    if _want("ntfy"):
        ntfy = build_ntfy_channel()
        if ntfy:
            register_channel(ntfy)
        else:
            logger.debug("ntfy not configured (NTFY_SERVER/TOPIC/USERNAME/PASSWORD missing)")

    logger.info("Notification registry ready: %d channel(s) active", len(_channels))


async def broadcast_report(report: dict) -> None:
    """
    Send a daily report to all registered channels concurrently.
    Individual channel failures are logged but don't affect other channels.
    """
    if not _channels:
        logger.warning("broadcast_report: no notification channels registered")
        return

    async def _safe_send(ch):
        try:
            await ch.send_report(report)
        except Exception as e:
            logger.error("Channel '%s' send_report failed: %s", ch.name, e)

    await asyncio.gather(*[_safe_send(ch) for ch in _channels])


async def broadcast_alert(message: str) -> None:
    """
    Send an alert message to all registered channels concurrently.
    Individual channel failures are logged but don't affect other channels.
    """
    if not _channels:
        logger.warning("broadcast_alert: no notification channels registered")
        return

    async def _safe_send(ch):
        try:
            await ch.send_alert(message)
        except Exception as e:
            logger.error("Channel '%s' send_alert failed: %s", ch.name, e)

    await asyncio.gather(*[_safe_send(ch) for ch in _channels])
