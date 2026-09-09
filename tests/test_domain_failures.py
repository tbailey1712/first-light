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


# ── Phase A severity ordering ────────────────────────────────────────────────

def test_critical_findings_survive_the_phase_a_cap():
    """Phase A caps suspicious_items at 10, in domain-completion order.

    On 2026-09-08 the wireless agent reported 3 critical findings and the list
    hit the cap at exactly 10; only one reached the report. Items must be
    ordered by severity before truncation so a late-finishing domain's criticals
    are not silently dropped in favour of an earlier domain's warnings.
    """
    items = (
        [{"severity": "warning", "value": f"w{i}", "source_domain": "firewall_threat"} for i in range(10)]
        + [{"severity": "critical", "value": f"c{i}", "source_domain": "wireless"} for i in range(3)]
    )
    items.sort(key=lambda i: 0 if i.get("severity") == "critical" else 1)
    kept = items[:10]

    criticals = [i for i in kept if i["severity"] == "critical"]
    assert len(criticals) == 3, "all critical findings must survive the cap"
    assert {i["value"] for i in criticals} == {"c0", "c1", "c2"}


def test_ordering_is_stable_within_a_severity():
    """Domain order must be preserved among equals, so output stays reproducible."""
    items = [
        {"severity": "warning", "value": "a"},
        {"severity": "critical", "value": "b"},
        {"severity": "warning", "value": "c"},
        {"severity": "critical", "value": "d"},
    ]
    items.sort(key=lambda i: 0 if i.get("severity") == "critical" else 1)
    assert [i["value"] for i in items] == ["b", "d", "a", "c"]


def test_missing_severity_is_treated_as_warning_not_critical():
    """A finding with no severity must not jump the queue ahead of real criticals."""
    items = [{"value": "unknown"}, {"severity": "critical", "value": "real"}]
    items.sort(key=lambda i: 0 if i.get("severity") == "critical" else 1)
    assert items[0]["value"] == "real"
