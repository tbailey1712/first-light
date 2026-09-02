"""Regression tests for the episodic-memory connection pool.

Episodic memory was write-only: `Episodic memory saved` on every run, while
`Failed to load repeat offender IPs` / `severity trends` failed every time and
`Episodic memory context injected` never appeared once. So repeat-offender and
severity-trend history never actually reached a synthesis prompt.

Cause: PostgresStore's pool is opened at graph start, then sits idle through the
~8-10 minute domain fan-out. Neon's serverless proxy closes idle connections
server-side, and the pool then hands the dead one to synthesis:
`consuming input failed: SSL connection has been closed unexpectedly`.

TCP keepalives cannot fix this — the close is a deliberate server-side action,
not a dropped network path. The pool has to validate on checkout instead.
"""

from psycopg_pool import ConnectionPool

from agent.episodic_memory import NEON_IDLE_CUTOFF_S, build_pool_config


def test_connections_are_validated_on_checkout():
    # The actual fix: without this the pool hands out a server-closed connection.
    assert build_pool_config()["check"] is ConnectionPool.check_connection


def test_idle_connections_are_recycled_before_neon_closes_them():
    cfg = build_pool_config()
    assert cfg["max_idle"] < NEON_IDLE_CUTOFF_S


def test_connections_are_retired_well_before_a_report_run_ends():
    # A full run is ~10 min; nothing should live long enough to go stale unnoticed.
    cfg = build_pool_config()
    assert cfg["max_lifetime"] <= 900


def test_tcp_keepalives_are_preserved():
    # Still worth having for genuine network drops, just not sufficient alone.
    kwargs = build_pool_config()["kwargs"]
    assert kwargs["keepalives"] == 1
    assert kwargs["keepalives_idle"] == 30


def test_pool_stays_small():
    cfg = build_pool_config()
    assert cfg["min_size"] >= 1
    assert cfg["max_size"] <= 3
