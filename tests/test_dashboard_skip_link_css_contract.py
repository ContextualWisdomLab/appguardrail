"""Regression tests for the dashboard skip-link stylesheet contract."""

from scanner.cli.appguardrail import dashboard_index_path


def test_dashboard_skip_link_css_uses_real_rule_boundaries():
    """Keep the focus-reveal selector outside escaped newline text."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    skip_rule_start = html.index(".skip-link{")
    focus_rule_start = html.index(".skip-link:focus{", skip_rule_start)
    css_between_rules = html[skip_rule_start:focus_rule_start]

    assert r"\n" not in css_between_rules
    assert css_between_rules.endswith("}\n  ")
