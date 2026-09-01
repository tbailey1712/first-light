"""Regression tests for LLM transient-failure retries (agent/llm.py).

Between 2026-06-23 and 2026-09-01, 39 of 69 daily reports (57%) completed with
at least one domain agent missing; on 2026-08-19 all eight failed and the report
was effectively empty. Every one was a `litellm.ServiceUnavailableError` (HTTP
503) from the model router. The retry loop covered InternalServerError (500) and
RateLimitError (429) but not 503, so the agent died on the first blip.

All eight domain agents fire simultaneously (ThreadPoolExecutor with
max_workers=8), so a fixed backoff makes them retry in lockstep and collide
again — hence the jitter requirement.
"""

import litellm
import pytest

from agent.llm import call_with_retries, is_retryable


def _exc(cls, msg="boom"):
    return cls(message=msg, llm_provider="anthropic", model="claude-sonnet-4-6")


class _Flaky:
    """Real callable that fails N times then succeeds — no mock framework."""

    def __init__(self, exc, fail_times):
        self.exc, self.fail_times, self.calls = exc, fail_times, 0

    def __call__(self):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.exc
        return "ok"


# --- which errors are worth retrying --------------------------------------

def test_service_unavailable_is_retryable():
    # The 503 that caused every one of the 82 observed agent failures.
    assert is_retryable(_exc(litellm.ServiceUnavailableError)) is True


def test_internal_server_error_is_retryable():
    assert is_retryable(_exc(litellm.InternalServerError)) is True


def test_rate_limit_is_retryable():
    assert is_retryable(_exc(litellm.RateLimitError)) is True


def test_api_connection_error_is_retryable():
    assert is_retryable(litellm.APIConnectionError(
        message="conn", llm_provider="anthropic", model="claude-sonnet-4-6")) is True


def test_programming_errors_are_not_retryable():
    # A bug in our own code must fail fast, not burn three attempts.
    assert is_retryable(ValueError("bad payload")) is False


# --- the retry loop --------------------------------------------------------

def test_recovers_from_a_transient_503():
    slept = []
    fn = _Flaky(_exc(litellm.ServiceUnavailableError), fail_times=2)
    assert call_with_retries(fn, retries=3, base_delay=5.0,
                             sleep=slept.append, jitter=lambda: 0.0) == "ok"
    assert fn.calls == 3


def test_gives_up_and_reraises_after_exhausting_retries():
    fn = _Flaky(_exc(litellm.ServiceUnavailableError), fail_times=99)
    with pytest.raises(litellm.ServiceUnavailableError):
        call_with_retries(fn, retries=3, base_delay=5.0,
                          sleep=lambda _: None, jitter=lambda: 0.0)
    assert fn.calls == 3


def test_non_retryable_error_fails_on_first_attempt():
    fn = _Flaky(ValueError("bad payload"), fail_times=99)
    with pytest.raises(ValueError):
        call_with_retries(fn, retries=3, base_delay=5.0,
                          sleep=lambda _: None, jitter=lambda: 0.0)
    assert fn.calls == 1


def test_backoff_is_exponential():
    slept = []
    fn = _Flaky(_exc(litellm.ServiceUnavailableError), fail_times=2)
    call_with_retries(fn, retries=3, base_delay=5.0,
                      sleep=slept.append, jitter=lambda: 0.0)
    assert slept == [5.0, 10.0]


def test_jitter_spreads_simultaneous_agents_apart():
    # Eight agents backing off to the identical instant just re-collide.
    slept = []
    fn = _Flaky(_exc(litellm.ServiceUnavailableError), fail_times=1)
    call_with_retries(fn, retries=3, base_delay=5.0,
                      sleep=slept.append, jitter=lambda: 0.4)
    assert slept == [5.4]


def test_success_on_first_call_never_sleeps():
    slept = []
    fn = _Flaky(_exc(litellm.ServiceUnavailableError), fail_times=0)
    assert call_with_retries(fn, retries=3, base_delay=5.0,
                             sleep=slept.append, jitter=lambda: 0.0) == "ok"
    assert fn.calls == 1 and slept == []
