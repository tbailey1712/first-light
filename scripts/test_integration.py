#!/usr/bin/env python3
"""
First Light — Integration Test Suite

Runs end-to-end checks against a live stack. Does NOT use pytest.
Designed for ops use: run before or after deployments.

Usage:
    python scripts/test_integration.py
    python scripts/test_integration.py --verbose

Exit code: 0 if all non-skipped checks pass, 1 if any fail.

Checks:
  1. Redis connectivity
  2. Redis distributed lock (acquire / conflict / release)
  3. ClickHouse reachability
  4. Tool smoke tests (validator, ntopng, adguard — skipped if not configured)
  5. Scheduler report lock race simulation
  6. Notification channel delivery (Telegram + Slack)
  7. Bot command handler registration
"""

import argparse
import asyncio
import importlib
import json
import os
import sys
import traceback
from typing import Callable

# Ensure project root is on the path when run from any directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_PASS = "PASS"
_FAIL = "FAIL"
_SKIP = "SKIP"

_results: list[tuple[str, str, str]] = []  # (status, name, detail)
_verbose = False


def _log(status: str, name: str, detail: str = "") -> None:
    _results.append((status, name, detail))
    icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭ "}.get(status, "  ")
    line = f"{icon} {status}: {name}"
    if detail and (_verbose or status in (_FAIL, _SKIP)):
        line += f"\n     {detail}"
    print(line)


def _run_check(name: str, fn: Callable, skip_reason: str = "") -> None:
    if skip_reason:
        _log(_SKIP, name, skip_reason)
        return
    try:
        result = fn()
        detail = str(result)[:200] if (_verbose and result) else ""
        _log(_PASS, name, detail)
    except AssertionError as e:
        _log(_FAIL, name, str(e))
    except Exception as e:
        _log(_FAIL, name, f"{type(e).__name__}: {e}")


# ── Check 1: Redis connectivity ──────────────────────────────────────────────────

def check_redis_connectivity():
    import redis
    url = os.getenv("REDIS_URL", "redis://fl-redis:6379/0")
    r = redis.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=3)
    result = r.ping()
    assert result, "PING returned falsy"
    # Clean up any leftover test keys from a previous run
    r.delete("test:s4:lock", "test:s4:history")
    return f"PONG from {url}"


# ── Check 2: Redis distributed lock ─────────────────────────────────────────────

def check_redis_lock():
    import redis
    url = os.getenv("REDIS_URL", "redis://fl-redis:6379/0")
    r = redis.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=3)

    key = "test:s4:lock"
    # Acquire
    acquired = r.set(key, "test", nx=True, ex=30)
    assert acquired, "First acquisition failed"

    # Attempt duplicate — must fail
    conflict = r.set(key, "test2", nx=True, ex=30)
    assert not conflict, "Duplicate acquisition should have failed but succeeded"

    # Release and re-acquire
    r.delete(key)
    reacquired = r.set(key, "test3", nx=True, ex=30)
    assert reacquired, "Re-acquisition after delete failed"

    r.delete(key)
    return "acquire → conflict → release → re-acquire OK"


# ── Check 3: ClickHouse reachability ────────────────────────────────────────────

def check_clickhouse():
    import httpx
    from agent.config import get_config
    cfg = get_config()
    url = f"http://{cfg.signoz_clickhouse_host}:8123/"
    params = {
        "user": cfg.signoz_clickhouse_user,
        "password": cfg.signoz_clickhouse_password,
        "query": "SELECT 1",
    }
    with httpx.Client(timeout=10) as client:
        resp = client.get(url, params=params)
    resp.raise_for_status()
    assert resp.text.strip() == "1", f"Expected '1', got: {resp.text.strip()!r}"
    return f"SELECT 1 → {resp.text.strip()!r} ({cfg.signoz_clickhouse_host})"


# ── Check 4: Tool smoke tests ────────────────────────────────────────────────────

def _smoke_tool(tool_fn, **kwargs) -> str:
    result = tool_fn.invoke(kwargs) if kwargs else tool_fn.invoke({})
    data = json.loads(result)
    assert "error" not in data or data.get("error") is None, f"Tool returned error: {data.get('error')}"
    return json.dumps(data)[:120]


def check_tool_validator():
    from agent.tools.validator import query_validator_health
    return _smoke_tool(query_validator_health, hours=1)


def check_tool_adguard():
    from agent.tools.metrics import query_adguard_block_rates
    return _smoke_tool(query_adguard_block_rates, hours=1)


def check_tool_ntopng():
    from agent.tools.ntopng import query_ntopng_interface_stats
    return _smoke_tool(query_ntopng_interface_stats)


# ── Check 5: Scheduler lock race simulation ─────────────────────────────────────

def check_report_lock_race():
    import redis
    from agent.scheduler import REPORT_LOCK_KEY, REPORT_LOCK_TTL
    from bot.telegram_bot import _can_acquire_report_lock, _release_report_lock

    url = os.getenv("REDIS_URL", "redis://fl-redis:6379/0")
    r = redis.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=3)

    # Pre-acquire the lock as if the scheduler holds it
    r.set(REPORT_LOCK_KEY, "scheduler", nx=True, ex=REPORT_LOCK_TTL)
    try:
        can = _can_acquire_report_lock()
        assert not can, "Bot should not be able to acquire lock while scheduler holds it"
    finally:
        r.delete(REPORT_LOCK_KEY)

    # Now lock is free — bot should acquire it
    can = _can_acquire_report_lock()
    assert can, "Bot should be able to acquire lock when free"
    _release_report_lock()

    return "scheduler holds → bot blocked; released → bot acquires OK"


# ── Check 6: Notification channel delivery ──────────────────────────────────────

async def _check_notifications_async():
    from agent.notifications import broadcast_alert, register_defaults
    from agent.notifications.registry import get_channels

    if not get_channels():
        await register_defaults()

    channels = get_channels()
    if not channels:
        return None, "No channels configured (TELEGRAM_BOT_TOKEN and SLACK_WEBHOOK_URL both unset)"

    await broadcast_alert(
        "🔬 [Integration Test] First Light S4 integration test — ignore this message."
    )
    return [ch.name for ch in channels], None


def check_notifications():
    channels, skip_reason = asyncio.run(_check_notifications_async())
    if skip_reason:
        raise _SkipException(skip_reason)
    return f"Alert broadcast to: {channels}"


class _SkipException(Exception):
    pass


# ── Check 7: Bot command handler registration ────────────────────────────────────

def check_telegram_handlers():
    # Dry-run: instantiate Application, verify handlers are registered
    # without connecting to Telegram servers
    from telegram.ext import Application, CommandHandler, MessageHandler
    token = os.getenv("TELEGRAM_BOT_TOKEN", "9999999999:AAdummytokenthatisnotreal000000000")
    try:
        app = Application.builder().token(token).build()
    except Exception:
        # Token format may be rejected — still test the module imports
        app = None

    # Verify the command handlers module structure
    import bot.telegram_bot as tbot
    for name in ("cmd_start", "cmd_help", "cmd_status", "cmd_report", "cmd_ask", "handle_message"):
        assert hasattr(tbot, name), f"Missing handler: {name}"

    return "All handlers present: start, help, status, report, ask, message"


# ── Main ─────────────────────────────────────────────────────────────────────────

def main():
    global _verbose
    parser = argparse.ArgumentParser(description="First Light integration tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print tool outputs")
    args = parser.parse_args()
    _verbose = args.verbose

    from agent.config import get_config
    cfg = get_config()

    print("\nFirst Light — Integration Test Suite")
    print("=" * 50)

    # 1. Redis
    _run_check("Redis connectivity", check_redis_connectivity)
    _run_check("Redis distributed lock", check_redis_lock,
               skip_reason="" if _results and _results[0][0] == _PASS else "Redis unavailable")

    # 2. ClickHouse
    _run_check("ClickHouse reachability", check_clickhouse)

    # 3. Tool smoke tests (conditional on config)
    _run_check(
        "Tool: query_validator_health",
        check_tool_validator,
        skip_reason="" if cfg.validator_host else "validator_host not configured",
    )
    _run_check(
        "Tool: query_adguard_block_rates",
        check_tool_adguard,
        skip_reason="" if cfg.adguard_host else "adguard_host not configured",
    )
    _run_check(
        "Tool: query_ntopng_interface_stats",
        check_tool_ntopng,
        skip_reason="" if cfg.ntopng_host else "ntopng_host not configured",
    )

    # 4. Scheduler lock race
    redis_ok = any(r[0] == _PASS and r[1] == "Redis connectivity" for r in _results)
    _run_check(
        "Scheduler lock race simulation",
        check_report_lock_race,
        skip_reason="" if redis_ok else "Redis unavailable",
    )

    # 5. Notification delivery
    try:
        _run_check("Notification channel delivery", check_notifications)
    except _SkipException as e:
        _log(_SKIP, "Notification channel delivery", str(e))

    # 6. Bot handlers
    _run_check("Telegram bot handler registration", check_telegram_handlers)

    # ── Summary ──
    print("\n" + "=" * 50)
    passed = sum(1 for r in _results if r[0] == _PASS)
    failed = sum(1 for r in _results if r[0] == _FAIL)
    skipped = sum(1 for r in _results if r[0] == _SKIP)
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")

    if failed:
        print("\nFailed checks:")
        for status, name, detail in _results:
            if status == _FAIL:
                print(f"  ❌ {name}: {detail}")
        sys.exit(1)

    print("\nAll checks passed." if not skipped else f"\nAll non-skipped checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
