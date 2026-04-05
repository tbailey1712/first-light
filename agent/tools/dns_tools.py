"""
DNS resolution tools — verify hostname-to-IP mappings without any auth.

Useful for the agent to validate findings before flagging them:
- "pve has a public DNS record" → check if it resolves via public DNS
- "device bypassing internal NTP" → verify if ntp.mcducklabs.com resolves locally
- "stale DNS entry for decommissioned host" → check if it still resolves
"""

import json
import socket
from typing import Optional

from langchain_core.tools import tool


@tool
def resolve_hostname(
    hostname: str,
    dns_server: Optional[str] = None,
) -> str:
    """Resolve a hostname to its IP addresses using the system DNS resolver.

    Use this to verify whether a hostname resolves before flagging it as
    missing, stale, or misconfigured. Also useful to confirm internal
    hostnames (e.g. pve.mcducklabs.com, adguard.mcducklabs.com) resolve
    to the expected internal IP.

    Args:
        hostname: Hostname or FQDN to resolve (e.g. "pve.mcducklabs.com")
        dns_server: Ignored (uses system resolver — AdGuard in this network).
                    Included for documentation clarity only.

    Returns:
        JSON with hostname, resolved IPs, and whether resolution succeeded.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
        ips = sorted({r[4][0] for r in results})
        return json.dumps({
            "hostname": hostname,
            "resolved": True,
            "ips": ips,
        })
    except socket.gaierror as e:
        return json.dumps({
            "hostname": hostname,
            "resolved": False,
            "error": str(e),
        })


@tool
def reverse_lookup_ip(ip: str) -> str:
    """Reverse-lookup an IP address to its hostname (PTR record) via system DNS.

    Use this to identify an unknown IP seen in logs, flows, or DNS anomalies.
    The system resolver is AdGuard, so internal hosts with PTR records will
    resolve to their local FQDN (e.g. 192.168.2.52 → ha.mcducklabs.com).

    Args:
        ip: IPv4 or IPv6 address to look up (e.g. "192.168.2.52")

    Returns:
        JSON with ip, hostname (if resolved), and whether resolution succeeded.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return json.dumps({"ip": ip, "resolved": True, "hostname": hostname})
    except socket.herror as e:
        return json.dumps({"ip": ip, "resolved": False, "error": str(e)})


@tool
def resolve_multiple_hostnames(hostnames: list[str]) -> str:
    """Resolve multiple hostnames in one call.

    Useful for bulk-checking whether a list of hostnames (e.g. from a
    Cloudflare DNS audit) resolve to internal vs. public IPs, or whether
    flagged public records (pve, portainer, pbs) actually exist.

    Args:
        hostnames: List of hostnames to resolve

    Returns:
        JSON with per-hostname results: resolved, ips or error.
    """
    results = []
    for hostname in hostnames:
        try:
            raw = socket.getaddrinfo(hostname, None)
            ips = sorted({r[4][0] for r in raw})
            results.append({"hostname": hostname, "resolved": True, "ips": ips})
        except socket.gaierror as e:
            results.append({"hostname": hostname, "resolved": False, "error": str(e)})

    return json.dumps({"results": results}, indent=2)
