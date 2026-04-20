"""
DNS resolution tools — verify hostname-to-IP mappings without any auth.

Useful for the agent to validate findings before flagging them:
- "pve has a public DNS record" → check if it resolves via public DNS
- "device bypassing internal NTP" → verify if ntp.mcducklabs.com resolves locally
- "stale DNS entry for decommissioned host" → check if it still resolves
"""

import json
import socket
import struct
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
    except (socket.herror, socket.gaierror) as e:
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


def _build_dns_query(hostname: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet (A record by default)."""
    # Header: ID=0xABCD, flags=0x0100 (standard query, recursion desired),
    # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in hostname.rstrip(".").split("."):
        question += struct.pack("B", len(label)) + label.encode()
    question += b"\x00"  # root label
    question += struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Skip a DNS name (handles both labels and compressed pointers)."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # pointer
            return offset + 2
        offset += length + 1
    return offset


def _parse_dns_response(data: bytes) -> list[str]:
    """Extract A-record IPs from a DNS response packet."""
    if len(data) < 12:
        return []

    # Check RCODE in flags — non-zero means error/NXDOMAIN
    flags = struct.unpack(">H", data[2:4])[0]
    rcode = flags & 0x0F
    if rcode != 0:
        return []

    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]

    # Skip question section
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(data, offset)
        offset += 4  # QTYPE(2) + QCLASS(2)

    ips = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        offset = _skip_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        if rtype == 1 and rdlength == 4:  # A record
            ips.append(socket.inet_ntoa(data[offset:offset + rdlength]))
        offset += rdlength
    return ips


@tool
def check_public_dns(hostnames: list[str]) -> str:
    """Check whether hostnames resolve via PUBLIC DNS (Google 8.8.8.8).

    Use this to verify if a subdomain (e.g. pve.mcducklabs.com) is exposed
    on the public internet. This bypasses the local AdGuard resolver and
    queries Google DNS directly. If a hostname does NOT resolve publicly,
    it is not exposed — do not flag it as a public DNS risk.

    Args:
        hostnames: List of FQDNs to check (e.g. ["pve.mcducklabs.com", "pbs.mcducklabs.com"])

    Returns:
        JSON with per-hostname results: publicly_resolves (bool), ips or error.
    """
    results = []
    for hostname in hostnames:
        try:
            query = _build_dns_query(hostname)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(query, ("8.8.8.8", 53))
            data, _ = sock.recvfrom(512)
            sock.close()
            ips = _parse_dns_response(data)
            results.append({
                "hostname": hostname,
                "publicly_resolves": len(ips) > 0,
                "ips": ips,
            })
        except Exception as e:
            results.append({
                "hostname": hostname,
                "publicly_resolves": None,
                "error": str(e),
            })
    return json.dumps({"results": results}, indent=2)
