"""
Hostname resolution utility.

Priority: reverse DNS → raw IP fallback.
Results are cached for the lifetime of the process to avoid repeated lookups
for the same IPs across tool calls in a single agent run.

DNS lookups run in a dedicated thread pool with a hard 2-second per-IP timeout
to prevent blocking the ReAct loop on unresolvable addresses.
"""

import re
import socket
import logging
import concurrent.futures
from functools import lru_cache

logger = logging.getLogger(__name__)

# Dedicated thread pool for blocking DNS calls — module-level singleton.
# max_workers=4 caps concurrent lookups; at 2s timeout each, worst case is 8s
# of wall-clock DNS time across parallel tool calls.
_dns_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="dns-resolve"
)

_PRIVATE_IP = re.compile(
    r'\b((?:192\.168|10|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\b'
)


@lru_cache(maxsize=512)
def resolve_hostname(ip: str) -> str:
    """
    Resolve an IP address to a hostname via reverse DNS.

    Uses a thread executor with a 2-second timeout so a single unresolvable
    address cannot stall the calling thread for the OS default (15–30s).

    Returns the short hostname (strips common private domain suffixes),
    or the raw IP if resolution fails or times out.

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
        future = _dns_executor.submit(socket.gethostbyaddr, ip)
        hostname, _, _ = future.result(timeout=2.0)
        # Strip common local domain suffixes for brevity
        for suffix in (".mcducklabs.com", ".local", ".internal", ".home", ".lan"):
            if hostname.endswith(suffix):
                return hostname[: -len(suffix)]
        return hostname
    except concurrent.futures.TimeoutError:
        logger.debug("DNS timeout for %s", ip)
        return ip
    except (socket.herror, socket.gaierror, OSError):
        return ip


def enrich_ip_column(text: str, max_lookups: int = 10) -> str:
    """
    Post-process tool output text, replacing bare private IPs with
    'hostname (ip)' format.

    Only replaces RFC-1918 addresses. Stops enriching after max_lookups
    distinct IPs to cap DNS call volume on large result sets.

    Args:
        text: Raw text containing IP addresses.
        max_lookups: Maximum number of distinct IPs to resolve (default 10).
                     IPs beyond this limit are left as raw addresses.

    Returns:
        Text with resolved private IPs replaced inline.
    """
    seen: dict[str, str] = {}

    def _replace(m: re.Match) -> str:
        ip = m.group(1)
        if ip not in seen:
            if len(seen) >= max_lookups:
                # Limit reached — leave remaining IPs unresolved
                seen[ip] = ip
            else:
                name = resolve_hostname(ip)
                seen[ip] = f"{name} ({ip})" if name != ip else ip
        return seen[ip]

    result = _PRIVATE_IP.sub(_replace, text)

    if len(seen) >= max_lookups:
        skipped = sum(1 for v in seen.values() if "(" not in v)
        if skipped:
            result += f"\n(+ {skipped} IPs not resolved — lookup limit reached)"

    return result
