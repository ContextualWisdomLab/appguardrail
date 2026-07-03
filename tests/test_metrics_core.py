from appguardrail_core.metrics import SaleReadinessInputs, score_sale_readiness


def _passing_inputs(**overrides):
    values = {
        "install_to_first_finding_minutes": 4.2,
        "zero_config_scan_rate": 0.98,
        "actionable_output_rate": 0.99,
        "fixture_precision_rate": 0.94,
        "duplicate_issue_suppression_rate": 0.995,
        "redaction_regression_pass_rate": 1.0,
        "optional_engine_fallback_clear": True,
        "pilot_organizations": 3,
        "active_repositories": 20,
        "recurring_failures_grouped": 50,
        "founder_reports_generated": 10,
        "buyer_diligence_exports": 5,
    }
    values.update(overrides)
    return SaleReadinessInputs(**values)


def test_score_sale_readiness_returns_sale_ready_when_all_targets_pass():
    score = score_sale_readiness(_passing_inputs())

    assert score.status == "sale-ready"
    assert score.passed == score.total == 12
    assert score.pass_rate == 1.0
    assert score.unmet == ()


def test_score_sale_readiness_allows_pilot_ready_without_critical_gaps():
    score = score_sale_readiness(
        _passing_inputs(
            actionable_output_rate=0.90,
            optional_engine_fallback_clear=False,
            active_repositories=18,
        )
    )

    assert score.status == "pilot-ready"
    assert score.passed == 9
    assert {metric.id for metric in score.unmet} == {
        "actionable_output_rate",
        "optional_engine_fallback_clear",
        "active_repositories",
    }


def test_score_sale_readiness_blocks_on_critical_buyer_gap():
    score = score_sale_readiness(
        _passing_inputs(
            install_to_first_finding_minutes=6,
            buyer_diligence_exports=3,
        )
    )

    assert score.status == "not-ready"
    assert {metric.id for metric in score.unmet} == {
        "time_to_first_finding",
        "buyer_diligence_exports",
    }


def test_score_sale_readiness_thresholds_are_strict_where_plan_says_above_or_under():
    score = score_sale_readiness(
        _passing_inputs(
            install_to_first_finding_minutes=5,
            zero_config_scan_rate=0.95,
            fixture_precision_rate=0.90,
            duplicate_issue_suppression_rate=0.99,
        )
    )

    assert {
        "time_to_first_finding",
        "zero_config_scan_rate",
        "fixture_precision_rate",
        "duplicate_issue_suppression_rate",
    } <= {metric.id for metric in score.unmet}
