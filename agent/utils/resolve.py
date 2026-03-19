"""
Hostname resolution utility.

Priority: reverse DNS → raw IP fallback.
Results are cached for the lifetime of the process to avoid repeated lookups
for the same IPs across tool calls in a single agent run.
"""

import socket
import logging
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)


@lru_cache(maxsize=512)
def resolve_hostname(ip: str) -> str:
    """
    Resolve an IP address to a hostname via reverse DNS.

    Returns the short hostname (strips domain if it ends in a private suffix),
    or the raw IP if resolution fails.

    Examples:
        "192.168.2.60"  → "roku-wifi"
        "192.168.2.52"  → "ha"
        "8.8.8.8"       → "dns.google"
        "10.0.0.999"    → "10.0.0.999"  (invalid, fallback)
    """
    if not ip or not isinstance(ip, str):
        return ip

    # Skip non-routable / multicast addresses
    if ip.startswith(("0.", "224.", "225.", "239.", "255.")):
        return ip

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Strip common local domain suffixes for brevity
        for suffix in (".mcducklabs.com", ".local", ".internal", ".home", ".lan"):
            if hostname.endswith(suffix):
                return hostname[: -len(suffix)]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ip


def enrich_ip_column(text: str) -> str:
    """
    Post-process tool output text, replacing bare IPs with 'hostname (ip)' format.

    Handles tab-separated rows from ClickHouse HTTP responses. Only replaces
    private RFC-1918 addresses to avoid slow lookups on public IPs.
    """
    import re

    _PRIVATE_IP = re.compile(
        r'\b((?:192\.168|10|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\b'
    )

    seen: dict[str, str] = {}

    def _replace(m: re.Match) -> str:
        ip = m.group(1)
        if ip not in seen:
            name = resolve_hostname(ip)
            seen[ip] = f"{name} ({ip})" if name != ip else ip
        return seen[ip]

    return _PRIVATE_IP.sub(_replace, text)
