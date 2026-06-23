"""Unit tests for the ingestion watchdog decision logic (agent/watchdog.py).

These cover the pure `decide()` function — no ClickHouse, Redis, or Docker I/O.
"""

from agent.watchdog import Decision, Freshness, decide

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


def test_logs_and_metrics_both_stale_alert_only():
    # Broader ClickHouse/collector outage -> restart won't help.
    d = _decide(log_lag=4 * 3600, metric_lag=4 * 3600)
    assert d.action == "alert_only"


def test_logs_stale_metrics_unknown_alert_only():
    d = _decide(log_lag=4 * 3600, metric_lag=None)
    assert d.action == "alert_only"


def test_staleness_boundary_is_inclusive():
    # lag exactly at threshold counts as stale (>=), not ok.
    assert _decide(log_lag=LOG_STALE_S, metric_lag=12).action == "restart"
    assert _decide(log_lag=LOG_STALE_S - 1, metric_lag=12).action == "ok"


def test_metric_freshness_boundary():
    # metric lag exactly at the fresh threshold is NOT fresh (>= fails fresh).
    assert _decide(log_lag=4 * 3600, metric_lag=METRIC_FRESH_S).action == "alert_only"
    assert _decide(log_lag=4 * 3600, metric_lag=METRIC_FRESH_S - 1).action == "restart"


def test_decision_is_dataclass_with_reason():
    d = _decide(log_lag=30, metric_lag=12)
    assert isinstance(d, Decision)
    assert d.reason  # non-empty explanation
