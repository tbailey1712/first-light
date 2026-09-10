"""Tests for lookup_device.

CLAUDE.md tells every agent to check docs/dhcp_leases.md before calling an
address unknown. Nothing let them: the shared context names the file but omits
its contents, and no tool read it.

On 2026-09-10 the daily report raised a CRITICAL -- "192.168.1.70 --
Unidentified host with privileged cross-domain access ... an unknown host made
privileged firewall changes" -- about `flanders`, a registered Apple machine on
line 122 of that table. The remediation it proposed was to check the very file
it could not open.

The negative answer carries just as much weight: an unregistered address on
VLAN 3 is what a rogue camera looked like. So "not registered" must be an
explicit, escalatable result rather than an empty one.
"""

import json

from agent.tools import device_lookup
from agent.tools.device_lookup import lookup_device


def _run(ident):
    device_lookup._load_leases.cache_clear()
    return json.loads(lookup_device.func(ident))


# ── the false positive this exists to prevent ────────────────────────────────

def test_the_flanders_false_positive():
    r = _run("192.168.1.70")
    assert r["registered"] is True
    assert r["hostname"] == "flanders"
    assert r["mac"] == "9c:76:0e:42:69:37"
    assert r["vendor"] == "Apple"


def test_lookup_by_mac_matches_the_same_device():
    for form in ("9c:76:0e:42:69:37", "9C-76-0E-42-69-37", "9c760e426937"):
        r = _run(form)
        assert r["registered"] is True, form
        assert r["hostname"] == "flanders", form


# ── the negative answer must stay loud ───────────────────────────────────────

def test_unregistered_on_isolated_vlan_is_escalated():
    """This is the rogue-camera shape: an address on VLAN 3 that isn't ours."""
    r = _run("192.168.3.134")
    assert r["registered"] is False
    assert r["vlan"].startswith("VLAN 3")
    assert "critical" in r["note"].lower()


def test_unregistered_on_a_normal_vlan_is_not_escalated():
    r = _run("192.168.1.218")
    assert r["registered"] is False
    assert "critical" not in r["note"].lower()


def test_randomised_mac_is_identified_as_such():
    """Locally-administered bit set. Expected on phones, so flagging it as an
    intruder without saying it's randomised would be misleading."""
    r = _run("c2:bb:8c:43:d8:15")
    assert r["registered"] is False
    assert r["randomised_mac"] is True

    r2 = _run("9c:76:0e:42:69:37")  # real burned-in Apple OUI
    assert r2["registered"] is True


# ── shape and robustness ─────────────────────────────────────────────────────

def test_vlan_is_derived_for_registered_devices():
    r = _run("192.168.3.11")
    assert r["registered"] is True
    assert r["vlan"].startswith("VLAN 3")
    assert r["hostname"] == "camera-front"


def test_notes_column_is_returned():
    """The notes carry operator knowledge the agent cannot get anywhere else."""
    r = _run("192.168.4.2")
    assert r["hostname"] == "vldtr"
    assert "validator" in r["notes"].lower()


def test_multiple_identifiers_in_one_call():
    r = _run("192.168.1.70, 192.168.3.134, 192.168.4.2")
    assert r["queried"] == 3
    assert r["registered"] == 2
    assert [x["query"] for x in r["results"]] == [
        "192.168.1.70", "192.168.3.134", "192.168.4.2",
    ]


def test_empty_input_is_handled():
    assert "error" in _run("   ")


def test_missing_lease_file_reports_clearly(tmp_path, monkeypatch):
    """A silent empty result would read as 'unregistered' and manufacture alerts."""
    monkeypatch.setattr(device_lookup, "_LEASES_FILE", tmp_path / "nope.md")
    device_lookup._load_leases.cache_clear()
    r = json.loads(lookup_device.func("192.168.1.70"))
    assert "error" in r
    assert r.get("registered") is not False, "must not claim a device is unregistered"
    device_lookup._load_leases.cache_clear()


def test_every_row_in_the_real_table_parses():
    """Guards against a formatting change silently dropping devices."""
    device_lookup._load_leases.cache_clear()
    by_ip, by_mac = device_lookup._load_leases()
    assert len(by_ip) > 130, f"only parsed {len(by_ip)} rows"
    assert len(by_mac) > 130, f"only parsed {len(by_mac)} MACs"
