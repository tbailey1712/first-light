"""
Slack notification channel.

Sends reports and alerts via the Slack Web API (incoming webhook or
bot token + channel). Uses an incoming webhook URL for simplicity —
no Socket Mode required for outbound-only notifications.

Set SLACK_WEBHOOK_URL in .env to enable. For interactive bot (S3-03),
SLACK_BOT_TOKEN and SLACK_APP_TOKEN are also needed.
"""

import logging
from typing import Optional

import httpx

from agent.utils.text import split_message

logger = logging.getLogger(__name__)

_SLACK_MAX_CHARS = 3000  # Slack block text limit is 3001; stay safe


class SlackWebhookChannel:
    """Sends reports and alerts via a Slack incoming webhook."""

    name = "slack"

    def __init__(self, webhook_url: str):
        self._webhook_url = webhook_url

    async def _post(self, text: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(self._webhook_url, json={"text": text})
            if resp.status_code == 200:
                return True
            logger.warning("Slack webhook failed: %s — %s", resp.status_code, resp.text[:200])
            return False
        except Exception as e:
            logger.error("Slack send error: %s", e)
            return False

    async def send_report(self, report: dict) -> None:
        """Send the daily report, chunking if needed."""
        report_text = report.get("report_text", "")
        header = f"*First Light Daily Report — {report.get('date', 'N/A')}*\n\n"

        full = header + report_text
        chunks = split_message(full, _SLACK_MAX_CHARS)
        for i, chunk in enumerate(chunks):
            suffix = f"\n_(part {i+1}/{len(chunks)})_" if len(chunks) > 1 else ""
            await self._post(chunk + suffix)

        logger.info("Report sent to Slack webhook")

    async def send_alert(self, message: str) -> None:
        """Send an alert message."""
        chunks = split_message(message, _SLACK_MAX_CHARS)
        for chunk in chunks:
            await self._post(chunk)


def build_slack_channel() -> Optional[SlackWebhookChannel]:
    """Build a SlackWebhookChannel from config, or None if not configured."""
    from agent.config import get_config
    cfg = get_config()
    if cfg.slack_webhook_url:
        return SlackWebhookChannel(cfg.slack_webhook_url)
    return None
