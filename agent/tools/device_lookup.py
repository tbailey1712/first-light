"""
Device identification against the DHCP lease table.

CLAUDE.md instructs every agent to check docs/dhcp_leases.md before asking the
user to identify an IP. Until now nothing gave them the means: the file is
mentioned in the shared context but its contents are not, and no tool read it.

The consequence was not cosmetic. On 2026-09-10 the daily report raised a
CRITICAL finding -- "192.168.1.70 - Unidentified host with privileged
cross-domain access ... an unknown host made privileged firewall changes" --
about a device sitting in the lease table as `flanders`, a registered Apple
machine belonging to the operator. Its own remediation step was "Confirm
192.168.1.70 in dhcp_leases.md immediately", which is the check it could not
perform.

The negative answer matters as much as the positive one: an address on an
isolated VLAN that is NOT in the table is exactly the signal that found a rogue
camera on the CCTV VLAN, so "not registered" is reported explicitly rather than
as an empty result.
"""

import json
import logging
import re
from functools import lru_cache
from pathlib import Path

from langchain_core.tools import tool

logger = logging.getLogger(__name__)

_LEASES_FILE = Path(__file__).parent.parent.parent / "docs" / "dhcp_leases.md"

# | IP | MAC (Vendor) | Hostname | Notes |
_ROW_RE = re.compile(
    r"^\|\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s*\|"
    r"\s*(?P<mac>[^|]+?)\s*\|"
    r"\s*(?P<hostname>[^|]*?)\s*\|"
    r"\s*(?P<notes>[^|]*?)\s*\|\s*$"
)
_MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", re.I)

_VLAN_NAMES = {
    "192.168.1.": "VLAN 1 (trusted LAN)",
    "192.168.2.": "VLAN 2 (IoT)",
    "192.168.3.": "VLAN 3 (CCTV, isolated)",
    "192.168.4.": "VLAN 4 (DMZ)",
    "192.168.10.": "VLAN 10 (guest)",
}


def _vlan_of(ip: str) -> str:
    for prefix, name in _VLAN_NAMES.items():
        if ip.startswith(prefix):
            return name
    return "unknown"


@lru_cache(maxsize=1)
def _load_leases() -> tuple[dict, dict]:
    """Parse the lease table into (by_ip, by_mac). Cached; call .cache_clear() to reload."""
    by_ip: dict[str, dict] = {}
    by_mac: dict[str, dict] = {}
    try:
        text = _LEASES_FILE.read_text()
    except FileNotFoundError:
        logger.warning("dhcp_leases.md not found at %s", _LEASES_FILE)
        return {}, {}

    for line in text.splitlines():
        m = _ROW_RE.match(line)
        if not m:
            continue
        mac_cell = m.group("mac")
        mac_match = _MAC_RE.search(mac_cell)
        vendor = re.search(r"\(([^)]+)\)", mac_cell)
        entry = {
            "ip": m.group("ip"),
            "mac": (mac_match.group(0).lower() if mac_match else mac_cell.strip()),
            "vendor": vendor.group(1) if vendor else "",
            "hostname": m.group("hostname"),
            "notes": m.group("notes"),
            "vlan": _vlan_of(m.group("ip")),
        }
        by_ip[entry["ip"]] = entry
        if mac_match:
            by_mac[entry["mac"]] = entry
    return by_ip, by_mac


def _normalise_mac(value: str) -> str | None:
    """Accept aa:bb:.., AA-BB-.., or aabbccddeeff and return colon-lowercase form."""
    raw = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(raw) != 12:
        return None
    raw = raw.lower()
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def _lookup_one(identifier: str) -> dict:
    by_ip, by_mac = _load_leases()
    ident = identifier.strip()

    if not by_ip and not by_mac:
        return {"query": ident, "error": "lease table unavailable — could not read docs/dhcp_leases.md"}

    if ident in by_ip:
        return {"query": ident, "registered": True, **by_ip[ident]}

    mac = _normalise_mac(ident)
    if mac and mac in by_mac:
        return {"query": ident, "registered": True, **by_mac[mac]}

    result = {"query": ident, "registered": False, "vlan": _vlan_of(ident)}
    if _MAC_RE.fullmatch(ident.lower()) or mac:
        # A locally administered bit in the first octet means a randomised MAC,
        # which is expected on phones and NOT by itself evidence of an intruder.
        first = (mac or ident).split(":")[0]
        try:
            result["randomised_mac"] = bool(int(first, 16) & 0x02)
        except ValueError:
            pass
    if result["vlan"].endswith("isolated)") or "DMZ" in result["vlan"]:
        result["note"] = (
            "NOT in the lease table, on an isolated VLAN with a fixed device "
            "inventory — treat as a critical finding."
        )
    else:
        result["note"] = "NOT in the lease table. May be a new or transient device."
    return result


@tool
def lookup_device(identifier: str) -> str:
    """Identify an IP or MAC against the DHCP lease table (docs/dhcp_leases.md).

    Call this BEFORE describing any address as unknown, unidentified or
    unregistered, and before asking the user to identify a device. Most
    addresses on this network are registered with a hostname and notes.

    Args:
        identifier: An IP ("192.168.1.70"), a MAC ("9c:76:0e:42:69:37",
            "9C-76-0E-42-69-37" and "9c760e426937" all work), or several of
            either separated by commas.

    Returns:
        JSON. Registered devices include hostname, MAC, vendor, VLAN and notes.
        Unregistered ones are reported explicitly with registered=false — on an
        isolated VLAN (3 or 4) that is itself a finding worth escalating.
    """
    idents = [i for i in re.split(r"[,\s]+", identifier.strip()) if i]
    if not idents:
        return json.dumps({"error": "no identifier supplied"})
    results = [_lookup_one(i) for i in idents[:20]]
    if len(results) == 1:
        return json.dumps(results[0], indent=2)
    return json.dumps({
        "queried": len(results),
        "registered": sum(1 for r in results if r.get("registered")),
        "results": results,
    }, indent=2)
