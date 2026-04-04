"""
pfSense XML-RPC tools — reads firewall config sections from pfSense.

pfSense exposes a subset of its config via XML-RPC at:
  https://{pfsense_host}/xmlrpc.php

Auth: HTTP Basic with pfsense_api_key as username and pfsense_api_secret as
password. SSL verification is disabled because pfSense ships a self-signed cert.

Available XML-RPC method:
  pfsense.backup_config_section(section_names: list[str]) -> base64-encoded XML

.env vars required:
  PFSENSE_HOST      IP or hostname of the pfSense firewall (no scheme)
  PFSENSE_USERNAME  pfSense user account created for XML-RPC access
  PFSENSE_PASSWORD  password for that account

IMPORTANT: Never SSH to pfSense (192.168.1.1). Use XML-RPC over HTTPS only.
"""

import base64
import json
import logging
import ssl
import urllib.request
import xmlrpc.client
from typing import Any
from xml.etree import ElementTree as ET

from langchain_core.tools import tool

from agent.config import get_config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom XML-RPC transport: Basic auth + disabled SSL verification
# ---------------------------------------------------------------------------

class _BasicAuthTransport(xmlrpc.client.SafeTransport):
    """SafeTransport subclass that adds Basic auth and skips SSL cert check."""

    def __init__(self, username: str, password: str) -> None:
        # Create an unverified SSL context
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        super().__init__(context=ctx)
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._auth_header = f"Basic {credentials}"

    def send_content(self, connection: Any, request_body: bytes) -> None:  # type: ignore[override]
        connection.putheader("Authorization", self._auth_header)
        super().send_content(connection, request_body)


def _get_proxy() -> xmlrpc.client.ServerProxy | None:
    """Build an XML-RPC proxy for pfSense, or return None if not configured."""
    cfg = get_config()
    host = getattr(cfg, "pfsense_host", None)
    username = getattr(cfg, "pfsense_username", None)
    password = getattr(cfg, "pfsense_password", None)

    if not host:
        return None
    if not username or not password:
        return None

    transport = _BasicAuthTransport(username, password)
    url = f"https://{host}/xmlrpc.php"
    return xmlrpc.client.ServerProxy(url, transport=transport, allow_none=True)


def _backup_section(section: str) -> ET.Element | dict:
    """
    Call pfsense.backup_config_section([section]) and return the parsed XML
    element for that section, or a dict with an 'error' key on failure.
    """
    proxy = _get_proxy()
    if proxy is None:
        cfg = get_config()
        if not getattr(cfg, "pfsense_host", None):
            return {"error": "pfsense_host not configured"}
        return {"error": "pfsense_username or pfsense_password not configured"}

    try:
        result = proxy.pfsense.backup_config_section([section])
    except xmlrpc.client.Fault as e:
        return {"error": f"XML-RPC fault {e.faultCode}: {e.faultString}"}
    except xmlrpc.client.ProtocolError as e:
        return {"error": f"XML-RPC protocol error {e.errcode}: {e.errmsg}"}
    except Exception as e:
        return {"error": f"XML-RPC call failed: {e}"}

    # pfSense returns the raw XML string directly
    xml_str: str = result if isinstance(result, str) else str(result)

    try:
        # The returned string is the XML fragment for the section, wrapped in
        # a root <pfsense> element by pfSense.
        root = ET.fromstring(xml_str)
        # If the root is already the section element, return it directly.
        child = root.find(section)
        return child if child is not None else root
    except ET.ParseError as e:
        return {"error": f"XML parse error: {e}", "raw": xml_str[:500]}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
def query_pfsense_firewall_rules() -> str:
    """Read NAT port-forward rules and firewall filter rules from pfSense via XML-RPC.

    Fetches the 'nat' config section (port forwards / 1:1 mappings) and the
    'filter' config section (pass/block rules). Useful for auditing what
    services are exposed to WAN and what traffic is permitted between VLANs.

    Returns:
        JSON with nat_rules (list of {interface, protocol, src, dst, target,
        description}) and firewall_rule_count. Returns {"error": "..."} if
        the XML-RPC call fails or credentials are not configured.
    """
    cfg = get_config()
    if not getattr(cfg, "pfsense_host", None):
        return json.dumps({"error": "pfsense_host not configured"})

    # --- NAT section ---
    nat_elem = _backup_section("nat")
    if isinstance(nat_elem, dict) and "error" in nat_elem:
        return json.dumps(nat_elem)

    nat_rules = []
    if nat_elem is not None:
        for rule in nat_elem.findall("rule"):
            # Each <rule> may have <interface>, <protocol>, <source>, <destination>,
            # <target>, <local-port>, and <descr> children.
            src_elem = rule.find("source")
            dst_elem = rule.find("destination")

            src = ""
            if src_elem is not None:
                src = src_elem.findtext("address") or src_elem.findtext("any") or ""
                if src == "":
                    src = "any" if src_elem.find("any") is not None else ""

            dst = ""
            if dst_elem is not None:
                dst_addr = dst_elem.findtext("address") or ""
                dst_port = dst_elem.findtext("port") or ""
                dst = f"{dst_addr}:{dst_port}".strip(":")

            nat_rules.append({
                "interface": rule.findtext("interface") or "",
                "protocol": rule.findtext("protocol") or "any",
                "src": src,
                "dst": dst,
                "target": rule.findtext("target") or "",
                "local_port": rule.findtext("local-port") or "",
                "description": rule.findtext("descr") or "",
            })

    # --- Filter section ---
    filter_elem = _backup_section("filter")
    if isinstance(filter_elem, dict) and "error" in filter_elem:
        # Partial success: we have NAT, report what we have plus the error
        return json.dumps({
            "nat_rules": nat_rules,
            "firewall_rule_count": None,
            "filter_error": filter_elem["error"],
        }, indent=2)

    rule_count = len(filter_elem.findall("rule")) if filter_elem is not None else 0

    return json.dumps({
        "nat_rules": nat_rules,
        "nat_rule_count": len(nat_rules),
        "firewall_rule_count": rule_count,
    }, indent=2)


@tool
def query_pfsense_dns_overrides() -> str:
    """Read Unbound DNS host overrides from pfSense config via XML-RPC.

    Host overrides are internal DNS entries that resolve local hostnames to
    private IPs. Useful for auditing what internal services are reachable by
    name and detecting unexpected or stale DNS entries.

    Returns:
        JSON with total count and host_overrides list of {hostname, domain,
        ip, description}. Returns {"error": "..."} if XML-RPC fails or
        credentials are not configured.
    """
    cfg = get_config()
    if not getattr(cfg, "pfsense_host", None):
        return json.dumps({"error": "pfsense_host not configured"})

    unbound_elem = _backup_section("unbound")
    if isinstance(unbound_elem, dict) and "error" in unbound_elem:
        return json.dumps(unbound_elem)

    host_overrides = []

    if unbound_elem is not None:
        for host in unbound_elem.findall("hosts"):
            hostname = host.findtext("host") or ""
            domain = host.findtext("domain") or ""
            ip = host.findtext("ip") or ""
            description = host.findtext("descr") or ""
            host_overrides.append({
                "hostname": hostname,
                "domain": domain,
                "fqdn": f"{hostname}.{domain}".strip("."),
                "ip": ip,
                "description": description,
            })

    return json.dumps({
        "total": len(host_overrides),
        "host_overrides": sorted(host_overrides, key=lambda x: x["fqdn"]),
    }, indent=2)
