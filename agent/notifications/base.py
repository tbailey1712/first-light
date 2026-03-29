"""
Notification channel Protocol.

Any class implementing send_report() and send_alert() qualifies as a
NotificationChannel via structural subtyping (no explicit inheritance needed).
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class NotificationChannel(Protocol):
    """Structural protocol for notification channels."""

    name: str

    async def send_report(self, report: dict) -> None:
        """Send a full daily report. report dict has: report_id, date, report_path, report_text."""
        ...

    async def send_alert(self, message: str) -> None:
        """Send a short alert or error message."""
        ...
