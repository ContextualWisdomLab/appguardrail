"""Regression tests for dashboard focus and live-region behavior."""

from scanner.cli.appguardrail import dashboard_index_path


def _dashboard_html() -> str:
    """Return the dashboard document as UTF-8 text."""
    return dashboard_index_path().read_text(encoding="utf-8")


def test_dashboard_uses_persistent_atomic_live_region() -> None:
    """Filter-result announcements must survive full dashboard rerenders."""
    html = _dashboard_html()

    assert 'id="findings-summary"' in html
    assert 'role="status"' in html
    assert 'aria-live="polite"' in html
    assert 'aria-atomic="true"' in html
    assert "liveSummary.textContent = summaryText" in html
    assert '<p class="sub" aria-live=' not in html


def test_dashboard_restores_focus_and_search_selection() -> None:
    """Rerenders must restore both the active control and search selection."""
    html = _dashboard_html()

    assert "const activeId = activeElement?.id || null;" in html
    assert "activeElement.selectionStart" in html
    assert "activeElement.selectionEnd" in html
    assert "restoredElement.focus();" in html
    assert (
        "restoredElement.setSelectionRange(activeSelection.start, activeSelection.end);"
        in html
    )
