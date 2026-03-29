"""
Telegram notification channel.

Migrated from agent/reports/daily_threat_assessment.py (send_report_notification)
and agent/scheduler.py (_notify_failure). Zero behavior change.
"""

import logging
from typing import Optional

import httpx

from agent.utils.text import split_message

logger = logging.getLogger(__name__)

_TELEGRAM_SAFE_CHARS = 4000


class TelegramChannel:
    """Sends reports and alerts to a Telegram chat via the Bot API."""

    name = "telegram"

    def __init__(self, bot_token: str, chat_id: str):
        self._token = bot_token
        self._chat_id = chat_id
        self._base = f"https://api.telegram.org/bot{bot_token}"

    async def _send(self, text: str, parse_mode: str = "Markdown") -> bool:
        """Send a single message. Returns True on success."""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{self._base}/sendMessage",
                    json={
                        "chat_id": self._chat_id,
                        "text": text,
                        "parse_mode": parse_mode,
                        "disable_web_page_preview": True,
                    },
                )
            if resp.status_code == 200:
                return True
            logger.warning("Telegram send failed: %s — %s", resp.status_code, resp.text[:200])
            return False
        except Exception as e:
            logger.error("Telegram send error: %s", e)
            return False

    async def send_report(self, report: dict) -> None:
        """Send the daily report, chunking if longer than Telegram's limit."""
        report_text = report.get("report_text", "")

        if len(report_text) > _TELEGRAM_SAFE_CHARS:
            # Send truncated summary + file path hint
            lines = report_text.split("\n")
            truncated = "\n".join(lines[:60])
            message = (
                f"{truncated}\n\n"
                f"_… Report truncated …_\n\n"
                f"📄 Full report: `{report.get('report_path', 'N/A')}`"
            )
            await self._send(message)
        else:
            await self._send(report_text)

        logger.info("Report sent to Telegram chat %s", self._chat_id)

    async def send_alert(self, message: str) -> None:
        """Send a short alert message, chunking only if necessary."""
        chunks = split_message(message, _TELEGRAM_SAFE_CHARS)
        for chunk in chunks:
            await self._send(chunk)

    async def send_message(self, text: str) -> None:
        """Send arbitrary text, splitting into chunks as needed."""
        chunks = split_message(text, _TELEGRAM_SAFE_CHARS)
        for chunk in chunks:
            await self._send(chunk)


def build_telegram_channel() -> Optional[TelegramChannel]:
    """Build a TelegramChannel from env config, or None if not configured."""
    from agent.config import get_config
    cfg = get_config()
    if cfg.telegram_bot_token and cfg.telegram_chat_id:
        return TelegramChannel(cfg.telegram_bot_token, cfg.telegram_chat_id)
    return None
