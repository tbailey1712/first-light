"""
Eval agent state definitions.

All TypedDicts used by the eval LangGraph graph.
"""

from typing import Any, Optional, TypedDict


class SynthesisInput(TypedDict):
    """Captured synthesis step inputs — stored as dataset item `input`."""

    synthesis_system_prompt: str
    synthesis_user_message: str
    date: str
    synthesis_prompt_version: Optional[int]


class CapturedTrace(TypedDict):
    """One historical daily-report trace extracted from Langfuse."""

    trace_id: str
    trace_name: str
    synthesis_input: SynthesisInput
    final_report: str  # actual production output (ground truth / expected_output)
    model: str
    date: str


class ExperimentScores(TypedDict):
    """Aggregated mean scores for one experiment run."""

    completeness: float
    actionability: float
    severity_accuracy: float
    format: float
    false_positive_rate: float
    composite: float


class RegressionResult(TypedDict):
    """Regression detection result for one dimension."""

    dimension: str
    current: float
    baseline: float
    delta: float
    regressed: bool
    below_minimum: bool


class EvalState(TypedDict):
    """Top-level state for the eval LangGraph graph."""

    days: int
    captured_traces: list[CapturedTrace]
    dataset_name: str
    dataset_items_stored: int
    experiment_scores: dict[str, ExperimentScores]  # {experiment_id: scores}
    experiment_urls: dict[str, Optional[str]]  # {experiment_id: langfuse_url}
    regressions: list[RegressionResult]
    new_champion: Optional[str]
    summary_posted: bool
