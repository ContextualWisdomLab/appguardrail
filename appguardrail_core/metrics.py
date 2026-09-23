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
    """One KPI result with enough context for dashboards and reports."""

    id: str
    label: str
    value: float | int | bool
    target: str
    passed: bool
    pillar: str


@dataclass(frozen=True)
class SaleReadinessScore:
    """Aggregate product-readiness score and unmet KPI list."""

    status: str
    passed: int
    total: int
    pass_rate: float
    metrics: tuple[MetricResult, ...]

    @property
    def unmet(self) -> tuple[MetricResult, ...]:
        return tuple(metric for metric in self.metrics if not metric.passed)


def score_sale_readiness(inputs: SaleReadinessInputs) -> SaleReadinessScore:
    """Score AppGuardrail against the current sale-readiness KPI contract."""
    metrics = (
        _metric(
            "time_to_first_finding",
            "Time from install to first useful finding",
            inputs.install_to_first_finding_minutes,
            "< 5 minutes",
            lambda value: value < 5,
            "activation",
        ),
        _metric(
            "zero_config_scan_rate",
            "First scans requiring no language/profile flags",
            inputs.zero_config_scan_rate,
            "> 95%",
            lambda value: value > 0.95,
            "activation",
        ),
        _metric(
            "actionable_output_rate",
            "Scans with an actionable next step",
            inputs.actionable_output_rate,
            "> 95%",
            lambda value: value > 0.95,
            "activation",
        ),
        _metric(
            "fixture_precision_rate",
            "Built-in fixture precision for deploy blockers",
            inputs.fixture_precision_rate,
            "> 90%",
            lambda value: value > 0.90,
            "quality",
        ),
        _metric(
            "duplicate_issue_suppression_rate",
            "Duplicate CI failure issue suppression on replay",
            inputs.duplicate_issue_suppression_rate,
            "> 99%",
            lambda value: value > 0.99,
            "quality",
        ),
        _metric(
            "redaction_regression_pass_rate",
            "Token/JWT/Authorization redaction regression pass rate",
            inputs.redaction_regression_pass_rate,
            "100%",
            lambda value: value >= 1.0,
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
            lambda value: value >= 3,
            "commercial",
        ),
        _metric(
            "active_repositories",
            "Active repositories under monitoring",
            inputs.active_repositories,
            ">= 20",
            lambda value: value >= 20,
            "commercial",
        ),
        _metric(
            "recurring_failures_grouped",
            "Recurring security failures grouped into issues",
            inputs.recurring_failures_grouped,
            ">= 50",
            lambda value: value >= 50,
            "commercial",
        ),
        _metric(
            "founder_reports_generated",
            "Founder-friendly reports generated from real scans",
            inputs.founder_reports_generated,
            ">= 10",
            lambda value: value >= 10,
            "commercial",
        ),
        _metric(
            "buyer_diligence_exports",
            "Buyer-diligence exports generated without manual editing",
            inputs.buyer_diligence_exports,
            ">= 5",
            lambda value: value >= 5,
            "commercial",
        ),
    )
    passed = sum(1 for metric in metrics if metric.passed)
    total = len(metrics)
    pass_rate = passed / total if total else 0.0
    return SaleReadinessScore(
        status=_status(pass_rate, metrics),
        passed=passed,
        total=total,
        pass_rate=pass_rate,
        metrics=metrics,
    )


def _metric(
    id: str,
    label: str,
    value: float | int | bool,
    target: str,
    predicate: Callable[[float | int | bool], bool],
    pillar: str,
) -> MetricResult:
    return MetricResult(
        id=id,
        label=label,
        value=value,
        target=target,
        passed=predicate(value),
        pillar=pillar,
    )


def _status(pass_rate: float, metrics: tuple[MetricResult, ...]) -> str:
    critical_unmet = {
        "time_to_first_finding",
        "zero_config_scan_rate",
        "fixture_precision_rate",
        "redaction_regression_pass_rate",
        "buyer_diligence_exports",
    }
    unmet_ids = {metric.id for metric in metrics if not metric.passed}
    if pass_rate == 1.0:
        return "sale-ready"
    if pass_rate >= 0.75 and not (unmet_ids & critical_unmet):
        return "pilot-ready"
    return "not-ready"
