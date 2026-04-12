"""
Node 4: Detect regressions and update champion.

Compares experiment scores against Redis baseline, flags regressions,
and promotes the best-scoring experiment as the new champion.
"""

import logging

from agent.evals.config import (
    MINIMUM_ACCEPTABLE_SCORES,
    REGRESSION_THRESHOLDS,
)
from agent.evals.registry import get_champion, load_baseline, save_baseline, set_champion
from agent.evals.state import EvalState, RegressionResult

logger = logging.getLogger(__name__)


def detect_regressions(state: EvalState) -> dict:
    """Compare scores to baseline, detect regressions, update champion."""
    scores = state["experiment_scores"]
    if not scores:
        return {"regressions": [], "new_champion": None}

    baseline = load_baseline()
    current_champion = get_champion()

    regressions: list[RegressionResult] = []

    # Only check the best-scoring experiment against baseline.
    # Other experiments being lower than baseline is expected (they're challengers),
    # not a regression. Below-minimum checks apply to all.
    best_exp = max(scores, key=lambda eid: scores[eid].get("composite", 0.0))

    for exp_id, exp_scores in scores.items():
        for dim, threshold in REGRESSION_THRESHOLDS.items():
            current_val = exp_scores.get(dim, 0.0)
            baseline_val = baseline.get(dim, 0.0)
            delta = current_val - baseline_val

            # Regression = best experiment dropped below baseline threshold
            regressed = (exp_id == best_exp) and baseline_val > 0 and delta < -threshold
            # Below minimum = any experiment is below absolute floor
            below_min = dim in MINIMUM_ACCEPTABLE_SCORES and current_val < MINIMUM_ACCEPTABLE_SCORES[dim]

            if regressed or below_min:
                regressions.append(RegressionResult(
                    dimension=f"{exp_id}/{dim}",
                    current=round(current_val, 3),
                    baseline=round(baseline_val, 3),
                    delta=round(delta, 3),
                    regressed=regressed,
                    below_minimum=below_min,
                ))

    if regressions:
        logger.warning(
            "Regressions detected: %s",
            [(r["dimension"], r["delta"]) for r in regressions],
        )

    # Determine new champion — highest composite score
    best_exp = max(scores, key=lambda eid: scores[eid].get("composite", 0.0))
    best_composite = scores[best_exp].get("composite", 0.0)
    new_champion = None

    baseline_composite = baseline.get("composite", 0.0)

    if best_composite > baseline_composite:
        new_champion = best_exp
        set_champion(best_exp)
        save_baseline(dict(scores[best_exp]))
        if baseline_composite == 0.0:
            logger.info("First eval run — seeding baseline from %s (composite=%.3f)", best_exp, best_composite)
        else:
            logger.info("New champion: %s (composite=%.3f, was %.3f)", best_exp, best_composite, baseline_composite)
    else:
        logger.info("No improvement over baseline (best=%.3f vs baseline=%.3f)", best_composite, baseline_composite)

    return {"regressions": regressions, "new_champion": new_champion}
