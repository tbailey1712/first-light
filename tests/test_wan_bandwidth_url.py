"""Regression test for query_wan_bandwidth_daily's ClickHouse URL.

The function built its endpoint from `config.signoz_clickhouse_url`, which has
never existed on FirstLightConfig -- the config exposes `signoz_clickhouse_host`
(plus `_user` / `_password`), and every other tool builds the URL as
f"http://{host}:8123".

Because the body is wrapped in a bare `except Exception`, the resulting
AttributeError never surfaced as a crash. It was swallowed and returned as
{"error": "..."}, so the weekly report's collect_network_performance step
silently produced no WAN bandwidth data:

    2026-09-06 09:00:02 agent.domains.weekly_report ERROR
      collect_network_performance failed: 'FirstLightConfig' object has no
      attribute 'signoz_clickhouse_url'

A tool that reports failure through its return value instead of raising needs a
test that inspects that value -- "it didn't throw" proves nothing here.
"""

import json
from unittest.mock import patch

from agent.tools import switch_tools
from agent.tools.switch_tools import _clickhouse_url, query_wan_bandwidth_daily


class _FakeResponse:
    """Minimal stand-in for the httpx response the tool expects."""

    def __init__(self, rows):
        self._rows = rows

    def raise_for_status(self):
        return None

    def json(self):
        return {"data": self._rows}


def _invoke(days=7):
    """Call through the @tool wrapper to the underlying function."""
    return query_wan_bandwidth_daily.func(days)


def test_url_comes_from_the_configured_clickhouse_host():
    # The helper already in this module is the single source of truth.
    assert _clickhouse_url().startswith("http://")
    assert _clickhouse_url().endswith(":8123")


def test_builds_a_usable_url_and_does_not_return_an_error():
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        return _FakeResponse([])

    with patch.object(switch_tools.httpx, "post", side_effect=fake_post):
        result = json.loads(_invoke())

    # The bug produced {"error": "'FirstLightConfig' object has no attribute ..."}
    assert "error" not in result, result.get("error")
    assert captured["url"] == f"{_clickhouse_url()}/"


def test_does_not_reference_a_nonexistent_config_attribute():
    # Guards the specific regression: the config has no such field, and
    # reintroducing it would be swallowed by the except-clause again.
    from agent.config import FirstLightConfig

    assert not hasattr(FirstLightConfig, "signoz_clickhouse_url")
    source = switch_tools.__file__
    with open(source) as fh:
        assert "signoz_clickhouse_url" not in fh.read()


def test_rows_are_converted_without_touching_config_again():
    rows = [{"day": "2026-09-05", "wan_download_gb": "12.34", "wan_upload_gb": "1.20"}]

    with patch.object(switch_tools.httpx, "post", return_value=_FakeResponse(rows)):
        result = json.loads(_invoke())

    assert "error" not in result, result.get("error")
    entry = result["wan_bandwidth_daily"][0]
    assert entry["date"] == "2026-09-05"
    # ClickHouse JSON returns numerics as strings; the tool must cast before adding.
    assert entry["wan_total_gb"] == 13.5
