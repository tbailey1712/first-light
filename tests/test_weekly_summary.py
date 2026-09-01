"""Regression tests for the weekly trend report (agent/reports/weekly_summary.py).

The weekly report raised `NameError: name 'datetime' is not defined` on every
Sunday 09:00 run from 2026-06-28 onward: the module imported `date` and
`timedelta` from `datetime` but never `datetime` itself, while
generate_weekly_report() calls `datetime.now()` twice. Each failure posted a red
"First Light scheduler error" to Slack and Pushover, so the only visible symptom
was a weekly alert — the report itself simply never existed.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

import agent.reports.weekly_summary as ws


@pytest.mark.asyncio
async def test_generate_weekly_report_produces_a_report(tmp_path, monkeypatch):
    monkeypatch.setattr(ws, "WEEKLY_REPORTS_DIR", tmp_path / "weekly")

    with patch(
        "agent.graphs.weekly_report_graph.generate_weekly_report",
        return_value="## Trends\n\nFirewall blocks down 12% week over week.",
    ):
        result = await ws.generate_weekly_report(hours=168)

    assert result["report_type"] == "weekly"
    assert "First Light — Weekly Trend Report" in result["report_text"]
    assert "Firewall blocks down 12%" in result["report_text"]
    assert Path(result["report_path"]).exists()


@pytest.mark.asyncio
async def test_weekly_report_header_carries_a_real_timestamp(tmp_path, monkeypatch):
    # Both datetime.now() calls are in the header; this is the line that raised.
    monkeypatch.setattr(ws, "WEEKLY_REPORTS_DIR", tmp_path / "weekly")

    with patch(
        "agent.graphs.weekly_report_graph.generate_weekly_report",
        return_value="body",
    ):
        result = await ws.generate_weekly_report()

    assert f"**Week ending:** {result['date']}" in result["report_text"]
    assert "**Generated:**" in result["report_text"]
