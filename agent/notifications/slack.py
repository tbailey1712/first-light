"""
Slack notification channel.

Sends reports and alerts via a Slack incoming webhook using Block Kit for
proper formatting. Converts Markdown (as written by the AI agent) to Slack
mrkdwn before posting.

Set SLACK_WEBHOOK_URL in .env to enable.
"""

import logging
import re
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Slack section block text limit
_BLOCK_MAX = 2900


def _md_to_mrkdwn(text: str) -> str:
    """Convert common Markdown patterns to Slack mrkdwn."""
    # Bold: **text** or __text__ → *text*
    text = re.sub(r"\*\*(.+?)\*\*", r"*\1*", text)
    text = re.sub(r"__(.+?)__", r"*\1*", text)
    # Italic: *text* or _text_ → _text_  (only single stars not already bold)
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"_\1_", text)
    # Strikethrough: ~~text~~ → ~text~
    text = re.sub(r"~~(.+?)~~", r"~\1~", text)
    # Inline code: `code` stays as-is (Slack supports backticks)
    # Headings: # / ## / ### → *Heading* (bold line)
    text = re.sub(r"^#{1,3}\s+(.+)$", r"*\1*", text, flags=re.MULTILINE)
    # Horizontal rules → divider hint (we'll handle in block builder)
    _DIVIDER_MARKER = "\x00DIVIDER\x00"
    text = re.sub(r"^---+$", _DIVIDER_MARKER, text, flags=re.MULTILINE)
    # Links: [text](url) → <url|text>
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r"<\2|\1>", text)
    return text


def _build_blocks(header: str, body: str) -> list[dict]:
    """
    Convert a report header + body into Slack Block Kit blocks.
    Splits on divider markers and section length limits.
    """
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": header[:150], "emoji": True}},
    ]

    # Split body on divider markers into sections
    parts = body.split("\x00DIVIDER\x00")
    for part in parts:
        part = part.strip()
        if not part:
            blocks.append({"type": "divider"})
            continue

        # Further split oversized sections on paragraph boundaries
        while len(part) > _BLOCK_MAX:
            split_at = part.rfind("\n\n", 0, _BLOCK_MAX)
            if split_at == -1:
                split_at = part.rfind("\n", 0, _BLOCK_MAX)
            if split_at == -1:
                split_at = _BLOCK_MAX
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": part[:split_at].strip()},
            })
            part = part[split_at:].strip()

        if part:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": part},
            })
        blocks.append({"type": "divider"})

    # Remove trailing divider
    if blocks and blocks[-1].get("type") == "divider":
        blocks.pop()

    return blocks


class SlackWebhookChannel:
    """Sends reports and alerts via a Slack incoming webhook."""

    name = "slack"

    def __init__(self, webhook_url: str):
        self._webhook_url = webhook_url

    async def _post(self, payload: dict) -> bool:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(self._webhook_url, json=payload)
            if resp.status_code == 200 and resp.text == "ok":
                return True
            logger.warning("Slack webhook failed: %s — %s", resp.status_code, resp.text[:200])
            return False
        except Exception as e:
            logger.error("Slack send error: %s", e)
            return False

    async def send_report(self, report: dict) -> None:
        """Send the daily report as formatted Block Kit blocks."""
        report_text = report.get("report_text", "")
        header = f"First Light Daily Report — {report.get('date', 'N/A')}"

        body = _md_to_mrkdwn(report_text)
        blocks = _build_blocks(header, body)

        # Slack webhooks accept max 50 blocks per message; split if needed
        chunk_size = 48  # leave room for header block across chunks
        for i in range(0, len(blocks), chunk_size):
            chunk = blocks[i:i + chunk_size]
            await self._post({"blocks": chunk})

        logger.info("Report sent to Slack webhook (%d blocks)", len(blocks))

    async def send_alert(self, message: str) -> None:
        """Send an alert as a simple mrkdwn section."""
        text = _md_to_mrkdwn(message)
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": text[:_BLOCK_MAX]}}]
        await self._post({"blocks": blocks})


def build_slack_channel() -> Optional[SlackWebhookChannel]:
    """Build a SlackWebhookChannel from config, or None if not configured."""
    from agent.config import get_config
    cfg = get_config()
    if cfg.slack_webhook_url:
        return SlackWebhookChannel(cfg.slack_webhook_url)
    return None
