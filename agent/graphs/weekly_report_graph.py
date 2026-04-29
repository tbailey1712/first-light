"""
Weekly Report Graph — LangGraph implementation.

Three-node graph that collects 7-day trend data via direct tool calls
(no ReAct loops), then synthesizes a weekly narrative with a single LLM call.

Flow:
  START
    └─ initialize       (fetch Langfuse prompt, load weekly baseline from Redis)
         └─ collect_trends   (parallel direct tool calls, no LLM)
              └─ synthesize  (single LLM call, saves new weekly baseline)
                   └─ END

Public interface:
    generate_weekly_report(hours=168) -> str
"""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Optional, TypedDict

from langgraph.graph import StateGraph, START, END
from langfuse import observe

from agent.domains.weekly_report import WEEKLY_COLLECTORS
from agent.langfuse_integration import get_prompt_manager
from agent.llm import chat

logger = logging.getLogger(__name__)

_REDIS_PREFIX = "fl:weekly_baseline:"
_REDIS_TTL = 777600  # 9 days

LANGFUSE_PROMPT = "first-light-weekly-synthesis"

# Baseline keys tracked across weekly runs
_BASELINE_KEYS = [
    "dns_queries_total", "dns_block_rate_pct", "firewall_blocks_total",
    "validator_balance_eth", "wan_bandwidth_avg_mbps",
]


# ── State ─────────────────────────────────────────────────────────────────────

class WeeklyReportState(TypedDict):
    session_id: str
    hours: int
    prompt: str                     # weekly synthesis prompt text
    baseline: dict[str, Any]        # last week's metrics from Redis
    infra_health: str               # pre-flight check JSON
    trend_data: dict[str, dict]     # collector_name -> structured results
    daily_reports: str              # concatenated daily report text for continuity tracking
    final_report: Optional[str]


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _get_redis():
    import redis as _redis
    from agent.config import get_config
    cfg = get_config()
    return _redis.from_url(cfg.redis_url, decode_responses=True)


def _load_weekly_baseline() -> dict[str, Any]:
    """Load last week's baseline metrics from Redis."""
    try:
        r = _get_redis()
        baseline = {}
        for k in _BASELINE_KEYS:
            val = r.get(f"{_REDIS_PREFIX}{k}")
            if val is not None:
                try:
                    baseline[k] = float(val)
                except ValueError:
                    baseline[k] = val
        return baseline
    except Exception as e:
        logger.warning("Weekly baseline load failed: %s", e)
        return {}


def _save_weekly_baseline(metrics: dict[str, Any]) -> None:
    """Save weekly baseline metrics to Redis for next week's comparison."""
    try:
        r = _get_redis()
        for k, v in metrics.items():
            if v is not None:
                r.set(f"{_REDIS_PREFIX}{k}", str(v), ex=_REDIS_TTL)
        logger.info("Weekly baseline saved: %s", list(metrics.keys()))
    except Exception as e:
        logger.warning("Weekly baseline save failed: %s", e)


def _format_weekly_baseline(baseline: dict[str, Any]) -> str:
    """Format weekly baseline as context for the synthesis prompt."""
    if not baseline:
        return ""
    lines = ["Last week's baseline (for comparison):"]
    labels = {
        "dns_queries_total": "DNS queries (7d total)",
        "dns_block_rate_pct": "DNS block rate",
        "firewall_blocks_total": "Firewall blocks (7d total)",
        "validator_balance_eth": "Validator balance (ETH)",
        "wan_bandwidth_avg_mbps": "WAN avg bandwidth (Mbps)",
    }
    for k, v in baseline.items():
        label = labels.get(k, k)
        lines.append(f"  {label}: {v}")
    return "\n".join(lines)


# ── Graph nodes ───────────────────────────────────────────────────────────────

def initialize(state: WeeklyReportState) -> dict:
    """Fetch weekly synthesis prompt and load baseline from Redis."""
    manager = get_prompt_manager()
    try:
        prompt = manager.get_prompt(LANGFUSE_PROMPT)
    except Exception as e:
        raise ValueError(
            f"Weekly synthesis prompt '{LANGFUSE_PROMPT}' not found in Langfuse: {e}"
        )

    baseline = _load_weekly_baseline()
    if baseline:
        logger.info("Weekly baseline loaded: %s", baseline)
    else:
        logger.info("No weekly baseline found — first run or expired")

    # Pre-flight infra health check (reuse from daily tools)
    infra_health_raw = "{}"
    try:
        from agent.tools.infra_health import query_reporting_infra_health
        infra_health_raw = query_reporting_infra_health.invoke({})
    except Exception as e:
        logger.error("Infra health check failed: %s", e)
        infra_health_raw = json.dumps({"overall": "unknown", "error": str(e)})

    # Load daily report files for continuity tracking — lets synthesis spot
    # recurring issues, unresolved action items, and patterns across the week
    daily_reports_text = ""
    try:
        from agent.reports.weekly_summary import _load_last_n_daily_reports
        daily = _load_last_n_daily_reports(7)
        if daily:
            parts = []
            for date_str, content in daily:
                parts.append(f"=== DAILY REPORT — {date_str} ===\n{content}")
            daily_reports_text = "\n\n".join(parts)
            logger.info("Loaded %d daily reports for weekly continuity tracking", len(daily))
    except Exception as e:
        logger.warning("Failed to load daily reports: %s", e)

    return {
        "prompt": prompt, "baseline": baseline,
        "infra_health": infra_health_raw, "daily_reports": daily_reports_text,
    }


def collect_trends(state: WeeklyReportState) -> dict:
    """Run all weekly collectors in parallel. No LLM calls — just tool invocations."""
    hours = state["hours"]
    results = {}

    def _run_collector(name: str, fn) -> tuple[str, dict]:
        start = time.monotonic()
        try:
            if name == "network_performance":
                data = fn(days=hours // 24)
            elif name in ("infrastructure_capacity", "validator_summary"):
                data = fn()
            else:
                data = fn(hours=hours)
            elapsed = time.monotonic() - start
            logger.info("Collector %s completed in %.1fs", name, elapsed)
            return name, data
        except Exception as e:
            logger.error("Collector %s failed: %s", name, e, exc_info=True)
            return name, {"error": str(e)}

    with ThreadPoolExecutor(max_workers=7, thread_name_prefix="weekly") as pool:
        futures = {
            pool.submit(_run_collector, name, fn): name
            for name, fn in WEEKLY_COLLECTORS.items()
        }
        for future in as_completed(futures, timeout=120):
            name, data = future.result()
            results[name] = data

    logger.info("All %d weekly collectors complete", len(results))
    return {"trend_data": results}


def synthesize(state: WeeklyReportState) -> dict:
    """Single LLM call to produce the weekly narrative report."""
    system_prompt = state["prompt"]

    baseline_context = _format_weekly_baseline(state.get("baseline", {}))
    if baseline_context:
        system_prompt = system_prompt + f"\n\n{baseline_context}"

    # Format trend data into user message
    date_str = datetime.now().strftime("%Y-%m-%d")
    hours = state["hours"]
    days = hours // 24

    sections = [
        f"Synthesize the following {days}-day trend data into the weekly First Light report.",
        f"Analysis period: week ending {date_str}, past {days} days",
        "",
        "---",
    ]

    # Infra health
    sections.append("\n## DATA PIPELINE HEALTH")
    sections.append(state.get("infra_health", "{}"))
    sections.append("\n---")

    # Each collector's data
    collector_labels = {
        "dns_trends": "DNS TRENDS",
        "firewall_trends": "FIREWALL & AUTH TRENDS",
        "wireless_health": "WIRELESS HEALTH",
        "network_performance": "NETWORK PERFORMANCE",
        "infrastructure_capacity": "INFRASTRUCTURE CAPACITY",
        "validator_summary": "ETHEREUM VALIDATOR",
        "security_posture": "SECURITY POSTURE",
    }

    for name, label in collector_labels.items():
        data = state.get("trend_data", {}).get(name, {})
        sections.append(f"\n## {label}")
        if isinstance(data, dict) and "error" in data:
            sections.append(f"Data collection failed: {data['error']}")
        else:
            sections.append(json.dumps(data, indent=2, default=str))
        sections.append("\n---")

    # Append daily reports for continuity tracking
    daily_reports = state.get("daily_reports", "")
    if daily_reports:
        sections.append("\n## DAILY REPORTS (for continuity tracking)")
        sections.append(
            "Below are the daily reports from this week. Use them to identify:\n"
            "- Recurring issues that appeared in multiple reports\n"
            "- Action items that were flagged but never resolved\n"
            "- Patterns or trends that daily anomaly detection noted\n"
            "Call out anything that keeps coming back or is getting worse."
        )
        sections.append(daily_reports)
        sections.append("\n---")

    sections.append("\nWrite the final weekly trend report now.")

    user_message = "\n".join(sections)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    logger.info("Running weekly synthesis...")
    response = chat(messages, "weekly", session_id=state["session_id"], agent_name="weekly_synthesis")
    final_report = response.choices[0].message.content or ""
    logger.info("Weekly synthesis complete.")

    # Extract and save baseline for next week
    new_baseline = _extract_weekly_baseline(state.get("trend_data", {}))
    if new_baseline:
        _save_weekly_baseline(new_baseline)

    return {"final_report": final_report}


def _extract_weekly_baseline(trend_data: dict[str, dict]) -> dict[str, Any]:
    """Extract key metrics from collector results for weekly baseline storage."""
    metrics: dict[str, Any] = {}

    dns = trend_data.get("dns_trends", {})
    if isinstance(dns, dict) and "error" not in dns:
        summary = dns.get("network_summary", {})
        if isinstance(summary, dict):
            if "total_queries" in summary:
                metrics["dns_queries_total"] = float(summary["total_queries"])
            if "block_rate_pct" in summary:
                metrics["dns_block_rate_pct"] = float(summary["block_rate_pct"])

    fw = trend_data.get("firewall_trends", {})
    if isinstance(fw, dict) and "error" not in fw:
        sec = fw.get("security_summary", {})
        if isinstance(sec, dict) and "total_blocks" in sec:
            metrics["firewall_blocks_total"] = float(sec["total_blocks"])

    validator = trend_data.get("validator_summary", {})
    if isinstance(validator, dict) and "error" not in validator:
        health = validator.get("validator_health", {})
        if isinstance(health, dict) and "balance_eth" in health:
            metrics["validator_balance_eth"] = float(health["balance_eth"])

    net = trend_data.get("network_performance", {})
    if isinstance(net, dict) and "error" not in net:
        wan = net.get("wan_bandwidth", {})
        if isinstance(wan, dict) and "avg_mbps" in wan:
            metrics["wan_bandwidth_avg_mbps"] = float(wan["avg_mbps"])

    return metrics


# ── Graph ─────────────────────────────────────────────────────────────────────

_builder = StateGraph(WeeklyReportState)
_builder.add_node("initialize", initialize)
_builder.add_node("collect_trends", collect_trends)
_builder.add_node("synthesize", synthesize)

_builder.add_edge(START, "initialize")
_builder.add_edge("initialize", "collect_trends")
_builder.add_edge("collect_trends", "synthesize")
_builder.add_edge("synthesize", END)

graph = _builder.compile()


# ── Public entrypoint ─────────────────────────────────────────────────────────

@observe(as_type="span", capture_input=False, capture_output=False)
def generate_weekly_report(hours: int = 168) -> str:
    """
    Run the weekly trend report pipeline via LangGraph.

    Args:
        hours: Lookback window (default 168 = 7 days)

    Returns:
        Final report markdown string
    """
    import uuid
    from langfuse import get_client as get_langfuse_client, LangfuseOtelSpanAttributes
    from opentelemetry import trace as otel_trace

    start = datetime.now(timezone.utc)
    session_id = f"weekly-report-{start.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    logger.info("=== Weekly Report Generation Start session=%s ===", session_id)

    lf = get_langfuse_client()
    span = otel_trace.get_current_span()
    span.set_attribute(LangfuseOtelSpanAttributes.TRACE_SESSION_ID, session_id)

    initial_state: WeeklyReportState = {
        "session_id": session_id,
        "hours": hours,
        "prompt": "",
        "baseline": {},
        "infra_health": "{}",
        "trend_data": {},
        "daily_reports": "",
        "final_report": None,
    }

    final = graph.invoke(initial_state)
    report = final.get("final_report", "")

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    logger.info("=== Weekly Report Generation Complete (%.1fs) session=%s ===", elapsed, session_id)

    lf.flush()
    return report
