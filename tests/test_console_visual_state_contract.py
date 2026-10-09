"""Regression contracts for visible dashboard interaction states."""

from scanner.cli.appguardrail import dashboard_index_path


def _console_html() -> str:
    """Return the standalone console document as UTF-8 text."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def test_console_hover_feedback_excludes_disabled_controls() -> None:
    """Enabled buttons must look interactive without styling disabled buttons as hoverable."""
    html = _console_html()

    assert "transition:filter 0.2s, opacity 0.2s" in html
    assert "button:hover:not(:disabled){filter:brightness(.94)}" in html


def test_console_busy_scan_rows_are_visually_and_pointer_disabled() -> None:
    """Busy rows must expose a visible wait state and reject duplicate pointer activation."""
    html = _console_html()

    assert 'tr.scan[aria-busy="true"]' in html
    assert "cursor: wait" in html
    assert "pointer-events: none" in html
