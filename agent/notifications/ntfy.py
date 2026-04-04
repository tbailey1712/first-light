"""
ntfy notification channel.

Sends critical alerts to a self-hosted ntfy instance via HTTP basic auth.
Reports are sent as a short summary (ntfy is for alerts, not full reports).

Set NTFY_SERVER, NTFY_TOPIC, NTFY_USERNAME, NTFY_PASSWORD in .env to enable.
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ntfy priority mapping based on message content keywords
_PRIORITY_HIGH = "high"
_PRIORITY_DEFAULT = "default"


def _priority(message: str) -> str:
    """Infer ntfy priority from message content."""
    lower = message.lower()
    if any(w in lower for w in ("critical", "down", "offline", "breach", "attack", "failed")):
        return _PRIORITY_HIGH
    return _PRIORITY_DEFAULT


class NtfyChannel:
    """Sends alerts to a self-hosted ntfy instance."""

    name = "ntfy"

    def __init__(self, server: str, topic: str, username: str, password: str):
        self._url = f"{server.rstrip('/')}/{topic}"
        self._auth = (username, password)

    async def send_report(self, report: dict) -> None:
        """Send a brief summary alert for the daily report (not the full text)."""
        date = report.get("date", "N/A")
        report_text = report.get("report_text", "")

        # Extract first non-empty line as a one-line summary
        summary = next(
            (line.strip().lstrip("#").strip() for line in report_text.splitlines() if line.strip()),
            "Daily report ready",
        )
        await self._post(
            title=f"First Light Report — {date}",
            message=summary[:200],
            priority=_PRIORITY_DEFAULT,
            tags=["clipboard"],
        )

    async def send_alert(self, message: str) -> None:
        """Send a critical alert."""
        lines = message.strip().splitlines()
        title = lines[0].lstrip("#").strip()[:100] if lines else "First Light Alert"
        body = "\n".join(lines[1:]).strip()[:500] if len(lines) > 1 else message[:500]
        await self._post(
            title=title,
            message=body or title,
            priority=_priority(message),
            tags=["rotating_light" if _priority(message) == _PRIORITY_HIGH else "bell"],
        )

    async def _post(self, title: str, message: str, priority: str, tags: list[str]) -> None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self._url,
                    auth=self._auth,
                    headers={
                        "Title": title,
                        "Priority": priority,
                        "Tags": ",".join(tags),
                    },
                    content=message.encode("utf-8"),
                )
            if resp.status_code == 200:
                logger.info("ntfy alert sent: %s", title)
            else:
                logger.warning("ntfy send failed: %s — %s", resp.status_code, resp.text[:200])
        except Exception as e:
            logger.error("ntfy send error: %s", e)


def build_ntfy_channel() -> Optional[NtfyChannel]:
    """Build an NtfyChannel from config, or None if not configured."""
    from agent.config import get_config
    cfg = get_config()
    if cfg.ntfy_server and cfg.ntfy_topic and cfg.ntfy_username and cfg.ntfy_password:
        return NtfyChannel(cfg.ntfy_server, cfg.ntfy_topic, cfg.ntfy_username, cfg.ntfy_password)
    return None
