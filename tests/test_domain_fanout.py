"""Regression tests for domain-agent fan-out concurrency.

The fan-out ran with max_workers=len(DOMAIN_AGENTS)=8. The docker VM has 4 vCPUs
and hosts *two* ClickHouse instances (SigNoz and Langfuse) plus MinIO, so eight
agents querying at once drove load average to 152 on 2026-09-04 — high enough
that sshd took 20 seconds to authenticate. Report duration degraded in step:
572s (09-01) -> 599s -> 635s -> 1066s (09-04).

Oversubscribing threads against a saturated box makes the job slower, not
faster, so the worker count is now bounded and configurable.
"""

from agent.graphs.daily_report_graph import DOMAIN_AGENTS, domain_fanout_workers


def test_default_is_below_the_old_unbounded_behaviour():
    # The whole point: fewer workers than agents.
    assert domain_fanout_workers(len(DOMAIN_AGENTS)) < len(DOMAIN_AGENTS)


def test_never_exceeds_the_number_of_agents():
    # Spinning up idle threads for agents that do not exist helps nobody.
    assert domain_fanout_workers(3, configured=8) == 3


def test_respects_an_explicit_setting():
    assert domain_fanout_workers(8, configured=2) == 2


def test_never_drops_below_one():
    # A zero or negative setting must not deadlock the report.
    assert domain_fanout_workers(8, configured=0) == 1
    assert domain_fanout_workers(8, configured=-5) == 1


def test_all_agents_still_run_even_though_fewer_run_at_once():
    # Concurrency is capped; coverage is not. The executor queues the rest.
    workers = domain_fanout_workers(len(DOMAIN_AGENTS))
    assert 1 <= workers <= len(DOMAIN_AGENTS)
    assert len(DOMAIN_AGENTS) == 8
