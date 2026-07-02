from appguardrail_core.external import build_external_scan_plan


def _available(*names):
    selected = set(names)

    def checker(name, version_args=("--version",)):
        return f"/usr/bin/{name}" if name in selected else None

    return checker


def test_build_external_scan_plan_auto_selects_python_web_engines():
    plan = build_external_scan_plan(
        {"python", "web"},
        external_mode="auto",
        zap_baseline_url="https://example.test",
        tool_available=_available("bandit", "ruff", "semgrep", "zap-baseline.py"),
    )

    assert plan.selected_names == ("bandit", "ruff", "semgrep", "zap")
    assert plan.bandit.auto_selected is True
    assert plan.ruff.auto_selected is True
    assert plan.semgrep.auto_selected is True
    assert plan.zap.auto_selected is True
    assert plan.trivy.should_run is False


def test_build_external_scan_plan_reports_missing_optional_auto_tools():
    plan = build_external_scan_plan(
        {"python"},
        external_mode="auto",
        tool_available=_available(),
    )

    assert plan.selected_names == ()
    assert plan.bandit.auto_applicable is True
    assert plan.bandit.skip_reason == "executable not found or not runnable"
    assert plan.ruff.skip_reason == "executable not found or not runnable"
    assert plan.semgrep.skip_reason == "executable not found or not runnable"
    assert plan.zap.skip_reason is None


def test_build_external_scan_plan_forced_engines_run_even_when_unavailable():
    plan = build_external_scan_plan(
        set(),
        external_mode="off",
        force_trivy=True,
        force_bandit=True,
        force_ruff=True,
        force_semgrep=True,
        zap_baseline_url="https://example.test",
        force_zap=True,
        tool_available=_available(),
    )

    assert plan.selected_names == ("trivy", "bandit", "ruff", "semgrep", "zap")
    assert all(decision.forced for decision in plan.decisions)
    assert not any(decision.available for decision in plan.decisions)


def test_build_external_scan_plan_java_typescript_needs_semgrep_not_python_tools():
    plan = build_external_scan_plan(
        {"java", "typescript"},
        external_mode="auto",
        tool_available=_available("semgrep"),
    )

    assert plan.selected_names == ("semgrep",)
    assert plan.bandit.auto_applicable is False
    assert plan.ruff.auto_applicable is False
    assert plan.semgrep.auto_applicable is True
