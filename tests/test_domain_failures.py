"""Regression tests for how a failed domain agent is represented.

Between 2026-06-23 and 2026-09-01, 39 of 69 daily reports completed with at
least one domain agent missing, and nobody noticed for two months. The reason:
a crashed agent was recorded with `overall_severity: "ok"`, so a domain that was
never analyzed looked identical to a domain that was analyzed and found healthy.
The same defaulting applied when an agent ran but emitted no parseable JSON.

"unknown" is not "ok". A domain we failed to look at must say so, in the report
and in the episodic severity trend.
"""

from agent.graphs.daily_report_graph import (
    failed_domain_result,
    format_unanalyzed_notice,
    unanalyzed_domains,
)


def test_crashed_agent_is_not_recorded_as_healthy():
    result = failed_domain_result("wireless", RuntimeError("503 Service Unavailable"))
    assert result["overall_severity"] == "unknown"


def test_crashed_agent_result_keeps_the_error_visible():
    result = failed_domain_result("wireless", RuntimeError("503 Service Unavailable"))
    assert result["domain"] == "wireless"
    assert "503 Service Unavailable" in result["summary"]


def test_crashed_agent_result_has_the_shape_downstream_nodes_expect():
    # correlate() and synthesize() index these keys unconditionally.
    result = failed_domain_result("dns_security", Exception("boom"))
    assert set(result) >= {
        "domain", "summary", "flagged_ips", "overall_severity", "findings", "metrics",
    }
    assert result["flagged_ips"] == []
    assert result["findings"] == []
    assert result["metrics"] == {}


def test_unanalyzed_domains_selects_only_unknown():
    results = [
        {"domain": "firewall_threat", "overall_severity": "ok"},
        {"domain": "wireless", "overall_severity": "unknown"},
        {"domain": "dns_security", "overall_severity": "critical"},
        {"domain": "validator", "overall_severity": "unknown"},
    ]
    assert unanalyzed_domains(results) == ["wireless", "validator"]


def test_a_fully_successful_run_has_no_unanalyzed_domains():
    results = [{"domain": "wireless", "overall_severity": "ok"}]
    assert unanalyzed_domains(results) == []


def test_no_notice_when_every_domain_was_analyzed():
    assert format_unanalyzed_notice([]) == ""


def test_notice_names_every_missing_domain_and_counts_them():
    notice = format_unanalyzed_notice(["wireless", "validator"])
    assert "wireless" in notice
    assert "validator" in notice
    assert "2 of 8" in notice


def test_notice_states_the_report_is_incomplete():
    # The whole point is that a reader cannot mistake this for an all-clear.
    notice = format_unanalyzed_notice(["wireless"])
    assert "NOT analyzed" in notice
