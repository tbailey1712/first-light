"""Regression tests for threat-intel enrichment row building.

The daily report of 2026-09-02 noted "no threat intel enrichment available (16%
pipeline coverage overall)" while reporting a live port-sweep source. The cause
was not API quota: the enricher looked IPs up successfully, then failed to store
almost every result. 180 `ClickHouse execute error: Client error '400 Bad
Request'` in 24 hours.

The INSERT body was assembled with an f-string that interpolated Python lists
directly, so `str(['hosting/datacenter'])` emitted SINGLE quotes:

    "categories": ['hosting/datacenter', 'threat-intel-flagged'],

That is not valid JSON, so ClickHouse rejected the whole row. A row survived
only when every list field happened to be empty — which is the 16%.

String fields were interpolated unescaped too, so an AS-owner containing a
double quote would break a row the same way.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "services" / "threat-intel-enricher" / "enricher.py"


def _load():
    # enricher.py imports its sibling `threat_intel` module by bare name.
    if str(_SRC.parent) not in sys.path:
        sys.path.insert(0, str(_SRC.parent))
    spec = importlib.util.spec_from_file_location("enricher_under_test", _SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


enricher_mod = _load()
build_enrichment_row = enricher_mod.build_enrichment_row


def _enrichment(**over):
    base = {
        "ip": "139.99.69.101",
        "enriched_at": "2026-09-02 08:44:00",
        "sources": {
            "abuseipdb": {"abuse_confidence_score": 0, "country_code": "SG",
                          "usage_type": "Data Center/Web Hosting/Transit"},
            "virustotal": {"harmless": 55, "as_owner": "OVH SAS", "country": "SG"},
            "alienvault": {"pulse_count": 23,
                           "pulses": ["ETIC Cybersecurity  2024-05-30  Port Scan",
                                      "2023 Port Scanners"],
                           "country_code": "SG"},
        },
        "threat_assessment": {
            "threat_score": 20, "is_malicious": False, "confidence": "high",
            "categories": ["hosting/datacenter", "threat-intel-flagged"],
            "recommendation": "allow",
        },
    }
    base.update(over)
    return base


def test_row_is_valid_json():
    # The whole bug in one assertion.
    json.loads(build_enrichment_row(_enrichment()))


def test_list_fields_use_json_arrays_not_python_repr():
    row = build_enrichment_row(_enrichment())
    assert "'" not in row.split('"alienvault_pulses"')[1].split("]")[0]
    parsed = json.loads(row)
    assert parsed["categories"] == ["hosting/datacenter", "threat-intel-flagged"]
    assert parsed["alienvault_pulses"][1] == "2023 Port Scanners"


def test_scalar_fields_survive_the_round_trip():
    parsed = json.loads(build_enrichment_row(_enrichment()))
    assert parsed["ip"] == "139.99.69.101"
    assert parsed["abuseipdb_country_code"] == "SG"
    assert parsed["virustotal_harmless"] == 55
    assert parsed["threat_score"] == 20
    assert parsed["is_malicious"] is False
    assert parsed["recommendation"] == "allow"


def test_quotes_in_a_string_field_do_not_break_the_row():
    e = _enrichment()
    e["sources"]["virustotal"]["as_owner"] = 'Some "Quoted" ISP, Inc.\\Backslash'
    parsed = json.loads(build_enrichment_row(e))
    assert parsed["virustotal_as_owner"] == 'Some "Quoted" ISP, Inc.\\Backslash'


def test_error_sources_are_collected_from_failed_lookups():
    e = _enrichment()
    e["sources"]["alienvault"] = {"error": "timeout"}
    parsed = json.loads(build_enrichment_row(e))
    assert parsed["error_sources"] == ["alienvault"]


def test_missing_sources_fall_back_to_defaults():
    parsed = json.loads(build_enrichment_row(
        {"ip": "1.2.3.4", "enriched_at": "2026-09-02 00:00:00"}))
    assert parsed["abuseipdb_score"] == 0
    assert parsed["categories"] == []
    assert parsed["confidence"] == "low"


def test_row_is_a_single_line_for_jsoneachrow():
    # JSONEachRow is newline-delimited; an embedded newline would split the row.
    assert "\n" not in build_enrichment_row(_enrichment())
