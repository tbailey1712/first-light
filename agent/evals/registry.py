"""
Redis registry for eval state — seen traces, baselines, champion tracking.

All methods are safe to call when Redis is unavailable (return sensible defaults).
"""

import json
import logging
from typing import Any, Optional

from agent.evals.config import (
    REDIS_BASELINE_KEY,
    REDIS_CHAMPION_KEY,
    REDIS_SEEN_TRACES_KEY,
)

logger = logging.getLogger(__name__)

_BASELINE_TTL = 30 * 86400  # 30 days
_SEEN_TRACE_TTL = 90 * 86400  # 90 days — don't re-process old traces


def _get_redis():
    import redis as _redis
    from agent.config import get_config

    cfg = get_config()
    return _redis.from_url(cfg.redis_url, decode_responses=True)


# ── Seen traces ──────────────────────────────────────────────────────────────


def get_seen_trace_ids() -> set[str]:
    try:
        r = _get_redis()
        return set(r.smembers(REDIS_SEEN_TRACES_KEY))
    except Exception as e:
        logger.warning("Redis: could not load seen traces: %s", e)
        return set()


def mark_traces_seen(trace_ids: list[str]) -> None:
    if not trace_ids:
        return
    try:
        r = _get_redis()
        r.sadd(REDIS_SEEN_TRACES_KEY, *trace_ids)
        r.expire(REDIS_SEEN_TRACES_KEY, _SEEN_TRACE_TTL)
    except Exception as e:
        logger.warning("Redis: could not mark traces seen: %s", e)


# ── Baseline scores ──────────────────────────────────────────────────────────


def load_baseline() -> dict[str, float]:
    try:
        r = _get_redis()
        raw = r.get(REDIS_BASELINE_KEY)
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.warning("Redis: could not load eval baseline: %s", e)
    return {}


def save_baseline(scores: dict[str, float]) -> None:
    try:
        r = _get_redis()
        r.set(REDIS_BASELINE_KEY, json.dumps(scores), ex=_BASELINE_TTL)
        logger.info("Eval baseline saved: %s", scores)
    except Exception as e:
        logger.warning("Redis: could not save eval baseline: %s", e)


# ── Champion ─────────────────────────────────────────────────────────────────


def get_champion() -> Optional[str]:
    try:
        r = _get_redis()
        return r.get(REDIS_CHAMPION_KEY)
    except Exception as e:
        logger.warning("Redis: could not load champion: %s", e)
        return None


def set_champion(experiment_id: str) -> None:
    try:
        r = _get_redis()
        r.set(REDIS_CHAMPION_KEY, experiment_id, ex=_BASELINE_TTL)
        logger.info("New eval champion: %s", experiment_id)
    except Exception as e:
        logger.warning("Redis: could not save champion: %s", e)
