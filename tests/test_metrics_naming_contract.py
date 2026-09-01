"""Naming-contract regressions for sale-readiness result objects."""

from dataclasses import fields, replace

from appguardrail_core.metrics import MetricResult, SaleReadinessScore


def test_metric_result_owns_semantic_multiword_fields() -> None:
    """Keep generic compatibility adapters out of the owned dataclass schema."""
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


def test_metric_result_accepts_legacy_constructor_and_replace_keywords() -> None:
    """Keep exported legacy keywords as adapters while storing semantic fields."""
    metric_result = MetricResult(
        id="fixture_precision_rate",
        label="Fixture precision",
        value=0.95,
        target="> 90%",
        passed=True,
        pillar="quality",
    )
    updated_metric_result = replace(
        metric_result,
        label="Updated precision",
        value=0.96,
        passed=False,
    )

    assert metric_result.metric_id == "fixture_precision_rate"
    assert metric_result.metric_label == "Fixture precision"
    assert metric_result.metric_value == 0.95
    assert metric_result.target_threshold == "> 90%"
    assert metric_result.target_passed is True
    assert metric_result.readiness_pillar == "quality"
    assert metric_result.id == metric_result.metric_id
    assert updated_metric_result.metric_label == "Updated precision"
    assert updated_metric_result.metric_value == 0.96
    assert updated_metric_result.target_passed is False


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


def test_sale_readiness_score_accepts_legacy_constructor_and_replace_keywords() -> None:
    """Keep exported aggregate compatibility across construction and replacement."""
    readiness_score = SaleReadinessScore(
        status="pilot-ready",
        passed=0,
        total=0,
        pass_rate=0.0,
        metrics=(),
    )
    updated_readiness_score = replace(
        readiness_score,
        status="sale-ready",
        passed=1,
        total=1,
    )

    assert readiness_score.readiness_status == "pilot-ready"
    assert readiness_score.passed_metric_count == 0
    assert readiness_score.total_metric_count == 0
    assert readiness_score.metric_results == ()
    assert readiness_score.status == readiness_score.readiness_status
    assert updated_readiness_score.readiness_status == "sale-ready"
    assert updated_readiness_score.passed_metric_count == 1
    assert updated_readiness_score.total_metric_count == 1
