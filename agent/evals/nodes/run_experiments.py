"""
Node 3: Run experiments — replay synthesis + judge (inline evaluator).

For each ExperimentConfig, calls langfuse.run_experiment() with the
synthesis replayer as task and the LLM judge as evaluator. Produces
per-experiment aggregated scores.
"""

import logging
from datetime import datetime, timezone

from agent.evals.config import (
    DATASET_NAME,
    DIMENSION_WEIGHTS,
    EXPERIMENTS,
)
from agent.evals.judge import DIMENSIONS, make_judge_evaluator
from agent.evals.state import EvalState, ExperimentScores
from agent.evals.synthesis_replayer import make_synthesis_task_fn
from agent.langfuse_integration import get_langfuse_client

logger = logging.getLogger(__name__)


def _compute_composite(scores: dict[str, float]) -> float:
    """Weighted composite score across all dimensions."""
    total = 0.0
    weight_sum = 0.0
    for dim, weight in DIMENSION_WEIGHTS.items():
        if dim in scores:
            total += scores[dim] * weight
            weight_sum += weight
    return total / weight_sum if weight_sum > 0 else 0.0


def _aggregate_item_scores(item_results: list) -> dict[str, float]:
    """Compute mean score per dimension across all items in an experiment."""
    dim_totals: dict[str, list[float]] = {d: [] for d in DIMENSIONS}

    for item_result in item_results:
        for evaluation in (item_result.evaluations or []):
            if evaluation.name in dim_totals and isinstance(evaluation.value, (int, float)):
                dim_totals[evaluation.name].append(float(evaluation.value))

    means = {}
    for dim, values in dim_totals.items():
        means[dim] = sum(values) / len(values) if values else 0.0
    return means


def run_experiments(state: EvalState) -> dict:
    """Run all configured experiments with inline judge evaluation."""
    lf = get_langfuse_client()

    # Load dataset items
    try:
        dataset = lf.get_dataset(DATASET_NAME)
        items = dataset.items
    except Exception as e:
        logger.error("Failed to load dataset '%s': %s", DATASET_NAME, e)
        return {"experiment_scores": {}, "experiment_urls": {}}

    if not items:
        logger.info("Dataset '%s' has no items — nothing to evaluate", DATASET_NAME)
        return {"experiment_scores": {}, "experiment_urls": {}}

    logger.info("Running %d experiments against %d dataset items", len(EXPERIMENTS), len(items))

    judge = make_judge_evaluator()
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    all_scores: dict[str, ExperimentScores] = {}
    all_urls: dict[str, str | None] = {}

    for config in EXPERIMENTS:
        exp_id = config["experiment_id"]
        run_name = f"{config['run_name_prefix']}-{run_ts}"

        logger.info(
            "Experiment '%s': model=%s, prompt_version=%s, %d items",
            exp_id, config["model"], config["synthesis_prompt_version"], len(items),
        )

        task_fn = make_synthesis_task_fn(config)

        try:
            result = lf.run_experiment(
                name=DATASET_NAME,
                run_name=run_name,
                description=config["description"],
                data=items,
                task=task_fn,
                evaluators=[judge],
                max_concurrency=2,  # conservative — each call is a full synthesis LLM call
                metadata={"experiment_id": exp_id, "model": config["model"]},
            )

            means = _aggregate_item_scores(result.item_results or [])
            composite = _compute_composite(means)

            all_scores[exp_id] = ExperimentScores(
                completeness=means.get("completeness", 0.0),
                actionability=means.get("actionability", 0.0),
                severity_accuracy=means.get("severity_accuracy", 0.0),
                format=means.get("format", 0.0),
                false_positive_rate=means.get("false_positive_rate", 0.0),
                composite=composite,
            )
            all_urls[exp_id] = getattr(result, "dataset_run_url", None)

            logger.info(
                "Experiment '%s' complete: composite=%.3f (%s)",
                exp_id, composite, {d: f"{v:.2f}" for d, v in means.items()},
            )

        except Exception as e:
            logger.error("Experiment '%s' failed: %s", exp_id, e, exc_info=True)
            all_scores[exp_id] = ExperimentScores(
                completeness=0.0, actionability=0.0, severity_accuracy=0.0,
                format=0.0, false_positive_rate=0.0, composite=0.0,
            )
            all_urls[exp_id] = None

    return {"experiment_scores": all_scores, "experiment_urls": all_urls}
