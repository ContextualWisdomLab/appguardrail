"""Sale-readiness KPI scoring for AppGuardrail product reviews."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class SaleReadinessInputs:
    """Measured inputs used to judge 2B KRW sale-readiness progress."""

    install_to_first_finding_minutes: float
    zero_config_scan_rate: float
    actionable_output_rate: float
    fixture_precision_rate: float
    duplicate_issue_suppression_rate: float
    redaction_regression_pass_rate: float
    optional_engine_fallback_clear: bool
    pilot_organizations: int
    active_repositories: int
    recurring_failures_grouped: int
    founder_reports_generated: int
    buyer_diligence_exports: int


@dataclass(frozen=True, init=False)
class MetricResult:
    """One KPI result with semantic stored fields and legacy adapters."""

    metric_id: str
    metric_label: str
    metric_value: float | int | bool
    target_threshold: str
    target_passed: bool
    readiness_pillar: str

    def __init__(
        self,
        metric_id: str | None = None,
        metric_label: str | None = None,
        metric_value: float | int | bool | None = None,
        target_threshold: str | None = None,
        target_passed: bool | None = None,
        readiness_pillar: str | None = None,
        *,
        id: str | None = None,  # noqa: A002 - compatibility keyword for exported API
        label: str | None = None,
        value: float | int | bool | None = None,
        target: str | None = None,
        passed: bool | None = None,
        pillar: str | None = None,
    ) -> None:
        """Construct semantic state while accepting legacy exported keywords."""
        resolved_metric_id = id if id is not None else metric_id
        resolved_metric_label = label if label is not None else metric_label
        resolved_metric_value = value if value is not None else metric_value
        resolved_target_threshold = target if target is not None else target_threshold
        resolved_target_passed = passed if passed is not None else target_passed
        resolved_readiness_pillar = pillar if pillar is not None else readiness_pillar
        if (
            resolved_metric_id is None
            or resolved_metric_label is None
            or resolved_metric_value is None
            or resolved_target_threshold is None
            or resolved_target_passed is None
            or resolved_readiness_pillar is None
        ):
            raise TypeError("MetricResult requires all metric contract fields")
        object.__setattr__(self, "metric_id", resolved_metric_id)
        object.__setattr__(self, "metric_label", resolved_metric_label)
        object.__setattr__(self, "metric_value", resolved_metric_value)
        object.__setattr__(self, "target_threshold", resolved_target_threshold)
        object.__setattr__(self, "target_passed", resolved_target_passed)
        object.__setattr__(self, "readiness_pillar", resolved_readiness_pillar)

    def __getattribute__(self, attribute_name: str) -> object:
        """Translate legacy read aliases without storing generic field names."""
        legacy_aliases = {
            "id": "metric_id",
            "label": "metric_label",
            "value": "metric_value",
            "target": "target_threshold",
            "passed": "target_passed",
            "pillar": "readiness_pillar",
        }
        semantic_name = legacy_aliases.get(attribute_name)
        if semantic_name is not None:
            return object.__getattribute__(self, semantic_name)
        return object.__getattribute__(self, attribute_name)


@dataclass(frozen=True, init=False)
class SaleReadinessScore:
    """Aggregate readiness score with semantic stored fields and legacy adapters."""

    readiness_status: str
    passed_metric_count: int
    total_metric_count: int
    pass_rate: float
    metric_results: tuple[MetricResult, ...]

    def __init__(
        self,
        readiness_status: str | None = None,
        passed_metric_count: int | None = None,
        total_metric_count: int | None = None,
        pass_rate: float | None = None,
        metric_results: tuple[MetricResult, ...] | None = None,
        *,
        status: str | None = None,
        passed: int | None = None,
        total: int | None = None,
        metrics: tuple[MetricResult, ...] | None = None,
    ) -> None:
        """Construct semantic state while accepting legacy exported keywords."""
        resolved_readiness_status = status if status is not None else readiness_status
        resolved_passed_metric_count = passed if passed is not None else passed_metric_count
        resolved_total_metric_count = total if total is not None else total_metric_count
        resolved_metric_results = metrics if metrics is not None else metric_results
        if (
            resolved_readiness_status is None
            or resolved_passed_metric_count is None
            or resolved_total_metric_count is None
            or pass_rate is None
            or resolved_metric_results is None
        ):
            raise TypeError("SaleReadinessScore requires all readiness score fields")
        object.__setattr__(self, "readiness_status", resolved_readiness_status)
        object.__setattr__(self, "passed_metric_count", resolved_passed_metric_count)
        object.__setattr__(self, "total_metric_count", resolved_total_metric_count)
        object.__setattr__(self, "pass_rate", pass_rate)
        object.__setattr__(self, "metric_results", resolved_metric_results)

    def __getattribute__(self, attribute_name: str) -> object:
        """Translate legacy read aliases without storing generic field names."""
        legacy_aliases = {
            "status": "readiness_status",
            "passed": "passed_metric_count",
            "total": "total_metric_count",
            "metrics": "metric_results",
            "unmet": "unmet_metrics",
        }
        semantic_name = legacy_aliases.get(attribute_name)
        if semantic_name is not None:
            return object.__getattribute__(self, semantic_name)
        return object.__getattribute__(self, attribute_name)

    @property
    def unmet_metrics(self) -> tuple[MetricResult, ...]:
        """Return metric results that have not met their target threshold."""
        return tuple(
            metric_result
            for metric_result in self.metric_results
            if not metric_result.target_passed
        )


def score_sale_readiness(inputs: SaleReadinessInputs) -> SaleReadinessScore:
    """Score AppGuardrail against the current sale-readiness KPI contract."""
    metric_results = (
        _metric(
            "time_to_first_finding",
            "Time from install to first useful finding",
            inputs.install_to_first_finding_minutes,
            "< 5 minutes",
            lambda metric_value: metric_value < 5,
            "activation",
        ),
        _metric(
            "zero_config_scan_rate",
            "First scans requiring no language/profile flags",
            inputs.zero_config_scan_rate,
            "> 95%",
            lambda metric_value: metric_value > 0.95,
            "activation",
        ),
        _metric(
            "actionable_output_rate",
            "Scans with an actionable next step",
            inputs.actionable_output_rate,
            "> 95%",
            lambda metric_value: metric_value > 0.95,
            "activation",
        ),
        _metric(
            "fixture_precision_rate",
            "Built-in fixture precision for deploy blockers",
            inputs.fixture_precision_rate,
            "> 90%",
            lambda metric_value: metric_value > 0.90,
            "quality",
        ),
        _metric(
            "duplicate_issue_suppression_rate",
            "Duplicate CI failure issue suppression on replay",
            inputs.duplicate_issue_suppression_rate,
            "> 99%",
            lambda metric_value: metric_value > 0.99,
            "quality",
        ),
        _metric(
            "redaction_regression_pass_rate",
            "Token/JWT/Authorization redaction regression pass rate",
            inputs.redaction_regression_pass_rate,
            "100%",
            lambda metric_value: metric_value >= 1.0,
            "quality",
        ),
        _metric(
            "optional_engine_fallback_clear",
            "External-engine fallback clarity",
            inputs.optional_engine_fallback_clear,
            "clear missing-tool output",
            bool,
            "quality",
        ),
        _metric(
            "pilot_organizations",
            "Pilot organizations or internal equivalents scanned weekly",
            inputs.pilot_organizations,
            ">= 3",
            lambda metric_value: metric_value >= 3,
            "commercial",
        ),
        _metric(
            "active_repositories",
            "Active repositories under monitoring",
            inputs.active_repositories,
            ">= 20",
            lambda metric_value: metric_value >= 20,
            "commercial",
        ),
        _metric(
            "recurring_failures_grouped",
            "Recurring security failures grouped into issues",
            inputs.recurring_failures_grouped,
            ">= 50",
            lambda metric_value: metric_value >= 50,
            "commercial",
        ),
        _metric(
            "founder_reports_generated",
            "Founder-friendly reports generated from real scans",
            inputs.founder_reports_generated,
            ">= 10",
            lambda metric_value: metric_value >= 10,
            "commercial",
        ),
        _metric(
            "buyer_diligence_exports",
            "Buyer-diligence exports generated without manual editing",
            inputs.buyer_diligence_exports,
            ">= 5",
            lambda metric_value: metric_value >= 5,
            "commercial",
        ),
    )
    passed_metric_count = sum(
        1 for metric_result in metric_results if metric_result.target_passed
    )
    total_metric_count = len(metric_results)
    pass_rate = (
        passed_metric_count / total_metric_count if total_metric_count else 0.0
    )
    return SaleReadinessScore(
        readiness_status=_status(pass_rate, metric_results),
        passed_metric_count=passed_metric_count,
        total_metric_count=total_metric_count,
        pass_rate=pass_rate,
        metric_results=metric_results,
    )


def _metric(
    metric_id: str,
    metric_label: str,
    metric_value: float | int | bool,
    target_threshold: str,
    target_predicate: Callable[[float | int | bool], bool],
    readiness_pillar: str,
) -> MetricResult:
    return MetricResult(
        metric_id=metric_id,
        metric_label=metric_label,
        metric_value=metric_value,
        target_threshold=target_threshold,
        target_passed=target_predicate(metric_value),
        readiness_pillar=readiness_pillar,
    )


def _status(pass_rate: float, metric_results: tuple[MetricResult, ...]) -> str:
    critical_unmet = {
        "time_to_first_finding",
        "zero_config_scan_rate",
        "fixture_precision_rate",
        "redaction_regression_pass_rate",
        "buyer_diligence_exports",
    }
    unmet_metric_ids = {
        metric_result.metric_id
        for metric_result in metric_results
        if not metric_result.target_passed
    }
    if pass_rate == 1.0:
        return "sale-ready"
    if pass_rate >= 0.75 and not (unmet_metric_ids & critical_unmet):
        return "pilot-ready"
    return "not-ready"
