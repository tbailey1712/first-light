"""
First Light notification channels.

Pluggable push notification system. Channels are registered at startup
based on which env vars are configured. Reports and alerts are broadcast
to all active channels.

Usage:
    from agent.notifications import broadcast_report, broadcast_alert, register_defaults

    await register_defaults()  # call once at startup
    await broadcast_report(report_dict)
    await broadcast_alert("Something went wrong: ...")
"""

from agent.notifications.base import NotificationChannel
from agent.notifications.registry import (
    register_channel,
    get_channels,
    broadcast_report,
    broadcast_alert,
    register_defaults,
)

__all__ = [
    "NotificationChannel",
    "register_channel",
    "get_channels",
    "broadcast_report",
    "broadcast_alert",
    "register_defaults",
]
