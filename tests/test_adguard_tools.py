"""Tests for the AdGuard query-log tools.

Context: the daily report flagged openwebui (192.168.2.15) with a TXT ratio of
47.74 and could say nothing more, because every existing adguard tool reads the
exporter's aggregate metrics out of ClickHouse -- counts and ratios, never a
domain name. These tools query AdGuard Home's own query log so a DNS finding
can be explained rather than just raised.

Two failure modes get their own assertions because they have different fixes:
a connect error means the VLAN 2 -> VLAN 1 firewall rule is missing, a 401
means the credentials are wrong. Collapsing them into a generic "error" would
send someone to the wrong place.
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx

from agent.tools import adguard_tools
from agent.tools.adguard_tools import (
    query_adguard_client_domains,
    query_adguard_txt_offenders,
)


def _now(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z")


def _entry(client, name, qtype, minutes_ago=1, reason="NotFilteredNotFound"):
    return {
        "client": client,
        "question": {"class": "IN", "name": name, "type": qtype},
        "reason": reason,
        "time": _now(minutes_ago),
    }


class _Resp:
    def __init__(self, payload, status=200):
        self._p, self.status_code, self.text = payload, status, json.dumps(payload)

    def json(self):
        return self._p


def _cfg(host="192.168.1.3", user="admin", pw="pw"):
    c = adguard_tools.get_config()
    class Shim:
        adguard_host = host
        adguard_port = 80
        adguard_username = user
        adguard_password = pw
        def __getattr__(self, n):  # fall through to the real config
            return getattr(c, n)
    return Shim()


def _run(fn, payload, **kw):
    with patch.object(adguard_tools, "get_config", return_value=_cfg()), \
         patch.object(adguard_tools.httpx, "Client") as C:
        C.return_value.__enter__.return_value.get.return_value = _Resp(payload)
        return json.loads(fn.func(**kw))


# ── the capability that was missing ───────────────────────────────────────────

def test_names_the_domains_behind_a_txt_ratio():
    payload = {"data": [
        _entry("192.168.2.15", "a.tunnel.example.com", "TXT"),
        _entry("192.168.2.15", "a.tunnel.example.com", "TXT"),
        _entry("192.168.2.15", "b.tunnel.example.com", "TXT"),
        _entry("192.168.2.15", "ollama.local", "A"),
    ]}
    r = _run(query_adguard_client_domains, payload, client_ip="192.168.2.15", query_type="TXT")

    assert r["records_matching"] == 3
    assert r["query_type_breakdown"] == {"TXT": 3, "A": 1}
    # The whole point: a name, not just a count.
    assert r["top_domains"][0] == {"domain": "a.tunnel.example.com", "count": 2}


def test_other_clients_are_excluded():
    # AdGuard's `search` param matches domains too, so client filtering must be explicit.
    payload = {"data": [
        _entry("192.168.2.15", "x.example.com", "TXT"),
        _entry("192.168.1.99", "x.example.com", "TXT"),
    ]}
    r = _run(query_adguard_client_domains, payload, client_ip="192.168.2.15")
    assert r["records_examined"] == 1


def test_entries_outside_the_window_are_dropped():
    payload = {"data": [
        _entry("192.168.2.15", "recent.example.com", "A", minutes_ago=5),
        _entry("192.168.2.15", "stale.example.com", "A", minutes_ago=60 * 40),
    ]}
    r = _run(query_adguard_client_domains, payload, client_ip="192.168.2.15", hours=24)
    assert [d["domain"] for d in r["top_domains"]] == ["recent.example.com"]


def test_blocked_queries_are_counted():
    payload = {"data": [
        _entry("192.168.2.15", "ads.example.com", "A", reason="FilteredBlackList"),
        _entry("192.168.2.15", "ok.example.com", "A"),
    ]}
    r = _run(query_adguard_client_domains, payload, client_ip="192.168.2.15")
    assert r["blocked"] == 1


def test_txt_offenders_groups_by_client():
    payload = {"data": [
        _entry("192.168.2.15", "t1.example.com", "TXT"),
        _entry("192.168.2.15", "t1.example.com", "TXT"),
        _entry("192.168.1.58", "t2.example.com", "TXT"),
        _entry("192.168.1.58", "plain.example.com", "A"),
    ]}
    r = _run(query_adguard_txt_offenders, payload)
    assert r["clients_with_txt"] == 2
    # Busiest client first, and A records excluded.
    assert list(r["clients"])[0] == "192.168.2.15"
    assert r["clients"]["192.168.2.15"]["txt_queries"] == 2
    assert r["clients"]["192.168.1.58"]["txt_queries"] == 1


# ── failure modes must stay distinguishable ───────────────────────────────────

def test_connect_failure_points_at_the_firewall():
    with patch.object(adguard_tools, "get_config", return_value=_cfg()), \
         patch.object(adguard_tools.httpx, "Client") as C:
        C.return_value.__enter__.return_value.get.side_effect = httpx.ConnectError("refused")
        r = json.loads(query_adguard_client_domains.func(client_ip="192.168.2.15"))
    assert "connect failed" in r["error"]
    assert "firewall" in r["hint"]


def test_401_points_at_credentials_not_the_firewall():
    with patch.object(adguard_tools, "get_config", return_value=_cfg()), \
         patch.object(adguard_tools.httpx, "Client") as C:
        C.return_value.__enter__.return_value.get.return_value = _Resp({}, status=401)
        r = json.loads(query_adguard_client_domains.func(client_ip="192.168.2.15"))
    assert "401" in r["error"]
    assert "password" in r["hint"]
    assert "firewall" not in r.get("hint", "")


def test_missing_credentials_are_reported_before_any_request():
    with patch.object(adguard_tools, "get_config", return_value=_cfg(user=None)), \
         patch.object(adguard_tools.httpx, "Client") as C:
        r = json.loads(query_adguard_client_domains.func(client_ip="192.168.2.15"))
        C.assert_not_called()
    assert "adguard_username" in r["error"]


def test_unconfigured_host_is_reported():
    with patch.object(adguard_tools, "get_config", return_value=_cfg(host=None)):
        r = json.loads(query_adguard_client_domains.func(client_ip="192.168.2.15"))
    assert "adguard_host" in r["error"]


def test_client_follows_redirects_and_tolerates_the_self_signed_cert():
    """AdGuard 307-redirects :80 to https and serves a self-signed cert.

    Unit tests with a mocked transport passed happily while the real call
    returned HTTP 307 and no data. Both flags are required for any request to
    reach AdGuard, so assert on how the client is constructed -- a mocked
    response can't catch a missing redirect policy.
    """
    payload = {"data": [_entry("192.168.2.15", "x.example.com", "TXT")]}
    with patch.object(adguard_tools, "get_config", return_value=_cfg()), \
         patch.object(adguard_tools.httpx, "Client") as C:
        C.return_value.__enter__.return_value.get.return_value = _Resp(payload)
        query_adguard_client_domains.func(client_ip="192.168.2.15")

    kwargs = C.call_args.kwargs
    assert kwargs.get("follow_redirects") is True, "307 to https would be returned as an error"
    assert kwargs.get("verify") is False, "self-signed LAN cert would fail verification"


def test_acme_challenge_pattern_is_reported_as_a_single_domain():
    """The real-world case this was built for.

    openwebui showed a TXT ratio of 48.66 that looked like DNS tunneling. It was
    495 lookups of one name -- a Let's Encrypt DNS-01 challenge retrying forever.
    The distinguishing signal is concentration: one domain, not many.
    """
    payload = {"data": [
        _entry("192.168.2.15", "_acme-challenge.openwebui.mcducklabs.com", "TXT")
        for _ in range(20)
    ]}
    r = _run(query_adguard_client_domains, payload, client_ip="192.168.2.15", query_type="TXT")
    assert len(r["top_domains"]) == 1
    assert r["top_domains"][0]["count"] == 20
    assert r["top_domains"][0]["domain"].startswith("_acme-challenge.")
