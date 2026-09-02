"""Regression contract for dashboard external-reference link accessibility."""

from scanner.cli.appguardrail import dashboard_index_path


def test_dashboard_external_reference_links_announce_new_tab_without_losing_purpose():
    """Reference links preserve their URL purpose while announcing the context change."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert 'target="_blank" rel="noopener"' in html
    assert 'aria-label="${esc(r)} (opens in a new tab)"' in html
    assert 'aria-label="(opens in a new tab)"' not in html
