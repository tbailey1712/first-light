"""
Hostname resolution utility — four-tier lookup chain.

Priority order per IP:
  1. topology.yaml device index  (zero latency, authoritative for known hosts)
  2. ntopng active hosts cache   (populated once per report run via prime_ntopng_cache)
  3. Reverse DNS with 2s timeout (PTR record via thread executor)
  4. Raw IP fallback

Results from tiers 1+2 are returned immediately without a network call.
Tier 3 results are cached via @lru_cache for the process lifetime so the
same IP is never looked up twice in a single run.

DNS lookups run in a dedicated thread pool with a hard 2-second per-IP
timeout to prevent blocking the ReAct loop on unresolvable addresses.
"""

import re
import socket
import logging
import concurrent.futures
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# ── Thread pool for blocking DNS calls ────────────────────────────────────────
# max_workers=4: worst case 4×2s = 8s of parallel DNS wait time
_dns_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="dns-resolve"
)

# ── Regex for RFC-1918 private addresses ──────────────────────────────────────
_PRIVATE_IP = re.compile(
    r'\b((?:192\.168|10|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\b'
)

# ── Tier 1: topology.yaml device index ────────────────────────────────────────
# Populated once at module import time. Maps ip -> short hostname.
_topology_index: dict[str, str] = {}

# ── Tier 2: ntopng active hosts cache ─────────────────────────────────────────
# Populated per report run via prime_ntopng_cache(). Maps ip -> hostname.
_ntopng_cache: dict[str, str] = {}


def _load_topology_index() -> dict[str, str]:
    """Index all known devices from topology.yaml by IP address."""
    index: dict[str, str] = {}
    try:
        topology_path = Path(__file__).parent.parent / "topology.yaml"
        if not topology_path.exists():
            return index
        with open(topology_path) as f:
            topology = yaml.safe_load(f) or {}

        devices = topology.get("devices", {})
        for device_key, info in devices.items():
            if not isinstance(info, dict):
                continue
            ip = info.get("ip")
            if not ip:
                continue
            # Prefer alt_hostname for dual-role hosts, else hostname, else device_key
            hostname = info.get("alt_hostname") or info.get("hostname") or device_key
            # Strip domain suffix for brevity
            for suffix in (".mcducklabs.com", ".local", ".internal", ".home", ".lan"):
                if hostname.endswith(suffix):
                    hostname = hostname[: -len(suffix)]
                    break
            index[ip] = hostname
    except Exception as e:
        logger.warning("Failed to load topology index: %s", e)
    return index


# Populate tier 1 at import time
_topology_index = _load_topology_index()


def prime_ntopng_cache(host_data: list[dict]) -> None:
    """Pre-populate the ntopng hostname cache for this report run.

    Call this once at the start of a report run with the output of
    query_ntopng_active_hosts(). Clears the previous cache before loading so
    stale entries from the prior run do not persist.

    Args:
        host_data: List of dicts containing at minimum 'ip' and 'name' keys.
                   Both 'ip' and 'ip_address' are accepted as the IP field;
                   both 'name' and 'hostname' are accepted as the name field.
    """
    global _ntopng_cache
    _ntopng_cache = {}
    for host in host_data:
        ip = host.get("ip") or host.get("ip_address")
        name = host.get("name") or host.get("hostname")
        if ip and name and name != ip:
            _ntopng_cache[ip] = name
    logger.debug("ntopng cache primed with %d hosts", len(_ntopng_cache))


@lru_cache(maxsize=512)
def resolve_hostname(ip: str) -> str:
    """Resolve an IP address to a display string via four-tier lookup.

    Returns 'hostname (ip)' if any name is found, or the raw IP if all tiers fail.

    Tier 1 (topology) and tier 2 (ntopng) never make network calls.
    Tier 3 (reverse DNS) runs in a thread executor with a 2-second timeout.

    Examples:
        "192.168.2.106"  → "nas (192.168.2.106)"      (topology index)
        "192.168.2.60"   → "roku-wifi (192.168.2.60)"  (PTR record)
        "10.0.0.255"     → "10.0.0.255"               (unresolvable, raw fallback)
    """
    if not ip or not isinstance(ip, str):
        return ip

    # Skip non-routable / multicast / broadcast
    if ip.startswith(("0.", "224.", "225.", "239.", "255.")):
        return ip

    # Tier 1: topology.yaml
    if ip in _topology_index:
        return f"{_topology_index[ip]} ({ip})"

    # Tier 2: ntopng cache
    if ip in _ntopng_cache:
        return f"{_ntopng_cache[ip]} ({ip})"

    # Tier 3: reverse DNS with timeout
    try:
        future = _dns_executor.submit(socket.gethostbyaddr, ip)
        hostname, _, _ = future.result(timeout=2.0)
        # Strip common local domain suffixes for brevity
        for suffix in (".mcducklabs.com", ".local", ".internal", ".home", ".lan"):
            if hostname.endswith(suffix):
                hostname = hostname[: -len(suffix)]
                break
        return f"{hostname} ({ip})"
    except concurrent.futures.TimeoutError:
        logger.debug("DNS timeout for %s", ip)
    except (socket.herror, socket.gaierror, OSError):
        pass

    # Tier 4: raw IP fallback
    return ip


def enrich_ip_column(text: str, max_lookups: int = 10) -> str:
    """Replace bare private IPs in text with 'hostname (ip)' format.

    Only processes RFC-1918 addresses. Stops enriching after max_lookups
    distinct IPs to cap DNS call volume on large result sets.

    Args:
        text: Raw text possibly containing IP addresses.
        max_lookups: Max distinct IPs to resolve via DNS (default 10).
                     IPs found in topology/ntopng tiers do not count toward
                     this limit as they require no network calls.

    Returns:
        Text with resolved IPs substituted inline.
    """
    seen: dict[str, str] = {}
    dns_lookups_used = 0

    def _replace(m: re.Match) -> str:
        nonlocal dns_lookups_used
        ip = m.group(1)
        if ip in seen:
            return seen[ip]

        # Check cheap tiers first — they don't count toward the limit
        if ip in _topology_index:
            result = f"{_topology_index[ip]} ({ip})"
            seen[ip] = result
            return result
        if ip in _ntopng_cache:
            result = f"{_ntopng_cache[ip]} ({ip})"
            seen[ip] = result
            return result

        # DNS lookup — enforce cap
        if dns_lookups_used >= max_lookups:
            seen[ip] = ip
            return ip

        dns_lookups_used += 1
        resolved = resolve_hostname(ip)
        seen[ip] = resolved
        return resolved

    result = _PRIVATE_IP.sub(_replace, text)

    # Append a note when the cap was hit and some IPs remain unresolved
    unresolved = sum(1 for k, v in seen.items() if v == k and k not in _topology_index and k not in _ntopng_cache)
    if dns_lookups_used >= max_lookups and unresolved:
        result += f"\n(+ {unresolved} IPs not resolved — lookup limit reached)"

    return result
