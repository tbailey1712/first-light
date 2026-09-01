"""Unit tests for the ingestion watchdog decision logic (agent/watchdog.py).

These cover the pure `decide()` function — no ClickHouse, Redis, or Docker I/O.
"""

from agent.watchdog import Decision, Freshness, decide, lag_from_rows, should_alert

LOG_STALE_S = 25 * 60      # 1500
METRIC_FRESH_S = 10 * 60   # 600


def _decide(log_lag, metric_lag, can_restart=True):
    return decide(
        Freshness(log_lag_s=log_lag, metric_lag_s=metric_lag),
        log_stale_s=LOG_STALE_S,
        metric_fresh_s=METRIC_FRESH_S,
        can_restart=can_restart,
    )


def test_logs_fresh_is_ok():
    assert _decide(log_lag=30, metric_lag=12).action == "ok"


def test_logs_fresh_ok_even_if_metrics_stale():
    # Metrics lagging doesn't matter while logs are flowing.
    assert _decide(log_lag=30, metric_lag=99999).action == "ok"


def test_log_lag_unknown_skips():
    # Can't reach ClickHouse -> don't act blind.
    d = _decide(log_lag=None, metric_lag=12)
    assert d.action == "skip"


def test_wedge_signature_restarts():
    # Logs stale, metrics fresh -> the wedge we auto-recover.
    d = _decide(log_lag=4 * 3600, metric_lag=12)
    assert d.action == "restart"


def test_wedge_but_guardrail_blocks_restart():
    d = _decide(log_lag=4 * 3600, metric_lag=12, can_restart=False)
    assert d.action == "alert_only"


def test_metric_lag_does_not_veto_a_restart():
    # Superseded by the 2026-08-21 incident: metric staleness is diagnostic
    # context, never a reason to withhold the restart. See the regression
    # tests below.
    assert _decide(log_lag=4 * 3600, metric_lag=4 * 3600).action == "restart"
    assert _decide(log_lag=4 * 3600, metric_lag=None).action == "restart"


def test_staleness_boundary_is_inclusive():
    # lag exactly at threshold counts as stale (>=), not ok.
    assert _decide(log_lag=LOG_STALE_S, metric_lag=12).action == "restart"
    assert _decide(log_lag=LOG_STALE_S - 1, metric_lag=12).action == "ok"


def test_metric_freshness_only_changes_the_reason_text():
    # Both restart now; the metric lag just labels which failure it looks like.
    wedge = _decide(log_lag=4 * 3600, metric_lag=METRIC_FRESH_S - 1)
    outage = _decide(log_lag=4 * 3600, metric_lag=METRIC_FRESH_S)
    assert wedge.action == outage.action == "restart"
    assert wedge.reason != outage.reason


def test_decision_is_dataclass_with_reason():
    d = _decide(log_lag=30, metric_lag=12)
    assert isinstance(d, Decision)
    assert d.reason  # non-empty explanation


# ---------------------------------------------------------------------------
# Regression tests for the 2026-08-21 outage.
#
# The collector lost a startup race against ClickHouse, failed to build its
# pipelines, and served NOTHING for 11 days. The watchdog saw it every 10
# minutes and refused to act, because both signals were stale and the old
# rule assumed "both stale == broader outage a restart can't fix". A restart
# was in fact the entire fix.
# ---------------------------------------------------------------------------

LOG_WINDOW_S = 4 * 3600


def test_both_stale_restarts_when_clickhouse_answered():
    # The Aug 21 signature: collector down, so logs AND metrics both stopped.
    # A non-None log_lag proves ClickHouse answered, so the collector is the
    # suspect and a restart is warranted.
    d = _decide(log_lag=4 * 3600, metric_lag=4 * 3600)
    assert d.action == "restart"


def test_logs_stale_metrics_unknown_restarts():
    # Can't read metrics but logs are provably stale -> still worth a restart;
    # the min-gap / daily-cap guardrails bound the blast radius.
    d = _decide(log_lag=4 * 3600, metric_lag=None)
    assert d.action == "restart"


def test_both_stale_still_respects_guardrail():
    d = _decide(log_lag=4 * 3600, metric_lag=4 * 3600, can_restart=False)
    assert d.action == "alert_only"


# --- lag_from_rows: the "max() over empty set returns 0" bug ---------------

def test_zero_max_timestamp_is_clamped_to_window():
    # ClickHouse max() over an EMPTY set of a non-nullable column returns 0,
    # not NULL. lag = now - 0 = ~1.79 billion seconds (56 years), which the
    # old code reported verbatim in every alert.
    assert lag_from_rows([{"lag_s": "1788299807"}], LOG_WINDOW_S) == LOG_WINDOW_S


def test_query_failure_is_unknown():
    assert lag_from_rows(None, LOG_WINDOW_S) is None


def test_no_rows_is_stale_beyond_window():
    assert lag_from_rows([], LOG_WINDOW_S) == LOG_WINDOW_S


def test_null_lag_is_stale_beyond_window():
    assert lag_from_rows([{"lag_s": None}], LOG_WINDOW_S) == LOG_WINDOW_S


def test_normal_lag_passes_through():
    # JSONEachRow returns ints as strings.
    assert lag_from_rows([{"lag_s": "7"}], LOG_WINDOW_S) == 7


def test_negative_lag_from_clock_skew_is_floored_at_zero():
    assert lag_from_rows([{"lag_s": "-42"}], LOG_WINDOW_S) == 0


# --- should_alert: stop the 10-minute notification flood -------------------

def test_first_problem_alert_is_sent():
    assert should_alert("alert_only", last_action=None,
                        seconds_since_last=None, repeat_after_s=21600) is True


def test_repeated_identical_alert_is_suppressed():
    # This is what produced ~1,500 Pushover + 1,500 Slack messages in 11 days.
    assert should_alert("alert_only", last_action="alert_only",
                        seconds_since_last=600, repeat_after_s=21600) is False


def test_repeated_alert_resent_after_repeat_window():
    assert should_alert("alert_only", last_action="alert_only",
                        seconds_since_last=21600, repeat_after_s=21600) is True


def test_action_change_always_alerts():
    assert should_alert("restart", last_action="alert_only",
                        seconds_since_last=60, repeat_after_s=21600) is True


def test_recovery_notifies_once():
    # Going healthy after a problem is worth exactly one message.
    assert should_alert("ok", last_action="alert_only",
                        seconds_since_last=600, repeat_after_s=21600) is True


def test_steady_healthy_state_is_silent():
    assert should_alert("ok", last_action=None,
                        seconds_since_last=None, repeat_after_s=21600) is False
    assert should_alert("ok", last_action="ok",
                        seconds_since_last=600, repeat_after_s=21600) is False
