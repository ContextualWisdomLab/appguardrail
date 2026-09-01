"""Naming-contract regressions for sale-readiness result objects."""

from dataclasses import fields

from appguardrail_core.metrics import MetricResult, SaleReadinessScore


def test_metric_result_owns_semantic_multiword_fields() -> None:
    """Keep generic compatibility accessors out of the owned dataclass schema."""
    field_names = {field.name for field in fields(MetricResult)}

    assert field_names == {
        "metric_id",
        "metric_label",
        "metric_value",
        "target_threshold",
        "target_passed",
        "readiness_pillar",
    }
    assert not field_names & {"id", "label", "value", "target", "passed", "pillar"}


def test_sale_readiness_score_owns_semantic_multiword_fields() -> None:
    """Name aggregate count, status, and metric fields by their readiness meaning."""
    field_names = {field.name for field in fields(SaleReadinessScore)}

    assert field_names == {
        "readiness_status",
        "passed_metric_count",
        "total_metric_count",
        "pass_rate",
        "metric_results",
    }
    assert not field_names & {"status", "passed", "total", "metrics"}
