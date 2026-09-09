"""Tests for per-client detail in query_wireless_health.

The tool reported wireless events as aggregates only:

    {"event_type": "disassociation", "total": 196,
     "per_ap": [{"ap": "UnifiBasement", "count": 77, "unique_clients": 7}]}

Counts per AP, and a bare unique_clients number. No MAC addresses. So the
wireless agent could see 196 disassociations and never say which device caused
them -- the finding was unactionable by construction.

That mattered on 2026-09-08: a smart meter's WiFi radio (d8:d5:b9:00:bb:9f) was
associating and dropping ~500 times a day across all three APs. It never showed
up in the report, and was only found by querying ClickHouse by hand. The
existing auth_failures query could not have caught it either -- that one only
matches STA_ASSOC_TRACKER failures, and this client completed its handshake
every time before dropping.
"""

import json
from unittest.mock import patch

from agent.tools import logs as logs_mod
from agent.tools.logs import query_wireless_health


def _rows(*dicts):
    return "\n".join(json.dumps(d) for d in dicts)


def _fake_clickhouse(events="", notables="", auth="", flapping=""):
    """Return a side_effect that feeds each of the four queries in call order."""
    payloads = [events, notables, auth, flapping]
    calls = {"n": 0}

    def side_effect(query, *a, **kw):
        # Identify by a distinctive fragment so ordering changes don't silently pass.
        if "unifi.event_type" in query and "GROUP BY event_type" in query:
            return events
        if "unifi.notable" in query:
            return notables
        if "STA_ASSOC_TRACKER" in query:
            return auth
        if "GROUP BY client_mac" in query:
            return flapping
        calls["n"] += 1
        return payloads[min(calls["n"] - 1, 3)]

    return side_effect


SMARTMETER = {
    "client_mac": "d8:d5:b9:00:bb:9f",
    "disassociations": 272,
    "associations": 505,
    "aps_seen": 3,
    "ap_names": ["UnifiBasement", "UnifiSecondFloorBack", "UniFiFirstFloorFront"],
}


def _run(**kw):
    with patch.object(logs_mod, "_execute_clickhouse_query", side_effect=_fake_clickhouse(**kw)):
        return json.loads(query_wireless_health.func(6))


def test_flapping_client_is_named():
    """The whole point: a MAC, not just a count."""
    r = _run(flapping=_rows(SMARTMETER))
    assert r["flapping_clients"][0]["client_mac"] == "d8:d5:b9:00:bb:9f"
    assert r["flapping_clients"][0]["disassociations"] == 272


def test_sorted_worst_offender_first():
    quiet = dict(SMARTMETER, client_mac="aa:bb:cc:dd:ee:ff", disassociations=9, associations=9)
    r = _run(flapping=_rows(SMARTMETER, quiet))
    macs = [c["client_mac"] for c in r["flapping_clients"]]
    assert macs[0] == "d8:d5:b9:00:bb:9f"


def test_roaming_and_dropping_are_distinguished():
    """These need different remedies, so they must not collapse into one label."""
    roamer = dict(SMARTMETER, client_mac="11:22:33:44:55:66", disassociations=40, associations=45, aps_seen=3)
    dropper = dict(SMARTMETER, client_mac="66:55:44:33:22:11", disassociations=90, associations=30, aps_seen=1)
    r = _run(flapping=_rows(roamer, dropper))
    by_mac = {c["client_mac"]: c["likely_cause"] for c in r["flapping_clients"]}
    assert "roaming" in by_mac["11:22:33:44:55:66"]
    assert "joining and dropping" in by_mac["66:55:44:33:22:11"]


def test_flapping_alone_is_enough_to_return_data():
    """Churn must not be hidden when no other wireless event type fired.

    The no_data guard previously ignored flapping entirely, so a run whose only
    signal was client churn would have returned status="no_data".
    """
    r = _run(flapping=_rows(SMARTMETER))
    assert r["status"] == "ok"
    assert len(r["flapping_clients"]) == 1


def test_no_data_still_reports_the_new_key():
    r = _run()
    assert r["status"] == "no_data"
    assert r["flapping_clients"] == []


def test_auth_failures_and_flapping_are_separate_signals():
    """A client that authenticates then drops is not an auth failure.

    The smart meter completed its 4-way handshake every time, so it would never
    appear in auth_failures no matter how badly it churned.
    """
    auth_row = {
        "mac": "de:ad:be:ef:00:01", "total_failures": 40, "ap_count": 2,
        "aps_seen": ["UnifiBasement", "UnifiSecondFloorBack"],
        "first_seen": 0, "last_seen": 0,
    }
    r = _run(auth=_rows(auth_row), flapping=_rows(SMARTMETER))
    assert [f["mac"] for f in r["auth_failures"]] == ["de:ad:be:ef:00:01"]
    assert [c["client_mac"] for c in r["flapping_clients"]] == ["d8:d5:b9:00:bb:9f"]
