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


@dataclass(frozen=True)
class MetricResult:
    """One KPI result with semantic owned names and compatibility accessors."""

    metric_id: str
    metric_label: str
    metric_value: float | int | bool
    target_threshold: str
    target_passed: bool
    readiness_pillar: str

    @property
    def id(self) -> str:
        """Return the legacy public metric identifier accessor."""
        return self.metric_id

    @property
    def label(self) -> str:
        """Return the legacy public metric label accessor."""
        return self.metric_label

    @property
    def value(self) -> float | int | bool:
        """Return the legacy public metric value accessor."""
        return self.metric_value

    @property
    def target(self) -> str:
        """Return the legacy public target-threshold accessor."""
        return self.target_threshold

    @property
    def passed(self) -> bool:
        """Return the legacy public target-pass result accessor."""
        return self.target_passed

    @property
    def pillar(self) -> str:
        """Return the legacy public readiness-pillar accessor."""
        return self.readiness_pillar


@dataclass(frozen=True)
class SaleReadinessScore:
    """Aggregate readiness score with semantic owned fields and legacy accessors."""

    readiness_status: str
    passed_metric_count: int
    total_metric_count: int
    pass_rate: float
    metric_results: tuple[MetricResult, ...]

    @property
    def unmet_metrics(self) -> tuple[MetricResult, ...]:
        """Return metric results that have not met their target threshold."""
        return tuple(metric for metric in self.metric_results if not metric.target_passed)

    @property
    def status(self) -> str:
        """Return the legacy public readiness-status accessor."""
        return self.readiness_status

    @property
    def passed(self) -> int:
        """Return the legacy public passed-metric count accessor."""
        return self.passed_metric_count

    @property
    def total(self) -> int:
        """Return the legacy public total-metric count accessor."""
        return self.total_metric_count

    @property
    def metrics(self) -> tuple[MetricResult, ...]:
        """Return the legacy public metric-results accessor."""
        return self.metric_results

    @property
    def unmet(self) -> tuple[MetricResult, ...]:
        """Return the legacy public unmet-metrics accessor."""
        return self.unmet_metrics


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
