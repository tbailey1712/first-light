"""
Eval agent configuration — experiment definitions, thresholds, and constants.
"""

from typing import Optional, TypedDict


class ExperimentConfig(TypedDict):
    experiment_id: str
    model: str
    synthesis_prompt_version: Optional[int]  # None = use stored production prompt
    temperature: float
    run_name_prefix: str
    description: str


EXPERIMENTS: list[ExperimentConfig] = [
    {
        "experiment_id": "sonnet-4-6-prod",
        "model": "claude-sonnet-4-6",
        "synthesis_prompt_version": None,
        "temperature": 0.3,
        "run_name_prefix": "sonnet-4-6",
        "description": "Baseline: current production model + prompt",
    },
    {
        "experiment_id": "gemma-4-31b",
        "model": "openai/gemma-4-31b",
        "synthesis_prompt_version": None,
        "temperature": 0.3,
        "run_name_prefix": "gemma-4-31b",
        "description": "Open-weight candidate: Gemma 4 31B",
    },
]

DATASET_NAME = "first-light-synthesis-eval"

JUDGE_MODEL = "claude-opus-4-6"
JUDGE_TEMPERATURE = 0.1

# Dimension weights for composite score
DIMENSION_WEIGHTS: dict[str, float] = {
    "completeness": 0.30,
    "actionability": 0.25,
    "severity_accuracy": 0.20,
    "format": 0.15,
    "false_positive_rate": 0.10,
}

# Regression thresholds — flag if score drops by more than this vs baseline
REGRESSION_THRESHOLDS: dict[str, float] = {
    "completeness": 0.05,
    "false_positive_rate": 0.08,
    "actionability": 0.05,
    "format": 0.10,
    "severity_accuracy": 0.08,
    "composite": 0.05,
}

# Absolute minimums — flag if score is below this regardless of baseline
MINIMUM_ACCEPTABLE_SCORES: dict[str, float] = {
    "completeness": 0.65,
    "actionability": 0.60,
    "composite": 0.65,
}

# Redis key prefixes for eval registry
REDIS_PREFIX = "fl:eval:"
REDIS_SEEN_TRACES_KEY = f"{REDIS_PREFIX}seen_traces"
REDIS_BASELINE_KEY = f"{REDIS_PREFIX}baseline"
REDIS_CHAMPION_KEY = f"{REDIS_PREFIX}champion"
