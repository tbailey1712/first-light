"""
Pushover notification channel.

Sends alerts and report summaries via the Pushover API.
Reports go as a brief summary (Slack handles the full report text).
Alerts map to Pushover priority based on content keywords.

Set PUSHOVER_TOKEN and PUSHOVER_USER_KEY in .env to enable.
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_PUSHOVER_URL = "https://api.pushover.net/1/messages.json"

# Pushover priority levels
_PRI_LOW    = -1
_PRI_NORMAL =  0
_PRI_HIGH   =  1


def _priority(message: str) -> int:
    lower = message.lower()
    if any(w in lower for w in ("critical", "down", "offline", "breach", "attack", "failed", "flapping")):
        return _PRI_HIGH
    return _PRI_NORMAL


class PushoverChannel:
    """Sends alerts and report summaries via Pushover."""

    name = "pushover"

    def __init__(self, token: str, user_key: str):
        self._token = token
        self._user = user_key

    async def send_report(self, report: dict) -> None:
        """Send a one-line report summary (Slack carries the full report)."""
        date = report.get("date", "N/A")
        report_text = report.get("report_text", "")
        summary = next(
            (line.strip().lstrip("#").strip() for line in report_text.splitlines() if line.strip()),
            "Daily report ready",
        )
        await self._post(
            title=f"First Light — {date}",
            message=summary[:512],
            priority=_PRI_LOW,  # Reports are low priority — no sound/vibration
        )

    async def send_alert(self, message: str) -> None:
        """Send a critical alert."""
        lines = message.strip().splitlines()
        title = lines[0].lstrip("#").strip()[:100] if lines else "First Light Alert"
        body = "\n".join(lines[1:]).strip()[:1000] if len(lines) > 1 else message[:1000]
        await self._post(
            title=title,
            message=body or title,
            priority=_priority(message),
        )

    async def _post(self, title: str, message: str, priority: int) -> None:
        payload = {
            "token":    self._token,
            "user":     self._user,
            "title":    title,
            "message":  message,
            "priority": priority,
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(_PUSHOVER_URL, data=payload)
            if resp.status_code == 200:
                logger.info("Pushover sent: %s", title)
            else:
                logger.warning("Pushover failed: %s — %s", resp.status_code, resp.text[:200])
        except Exception as e:
            logger.error("Pushover error: %s", e)


def build_pushover_channel() -> Optional[PushoverChannel]:
    """Build a PushoverChannel from config, or None if not configured."""
    from agent.config import get_config
    cfg = get_config()
    if cfg.pushover_token and cfg.pushover_user_key:
        return PushoverChannel(cfg.pushover_token, cfg.pushover_user_key)
    return None
