"""Regression tests for the standalone console accessibility contract."""

from scanner.cli.appguardrail import dashboard_index_path


def _console_html() -> str:
    """Return the standalone console document as UTF-8 text."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def test_console_table_headers_have_explicit_column_scope():
    """Both console tables must expose every header as a column header."""
    html = _console_html()

    assert html.count('scope="col"') == 10
    assert '<th scope="col">When</th>' in html
    assert '<th scope="col">Severity</th>' in html


def test_console_rows_preserve_cell_content_for_screen_readers():
    """Interactive rows must use a tooltip without replacing cell semantics."""
    html = _console_html()

    assert 'role="button" title="View scan details"' in html
    assert 'aria-label="View scan details"' not in html

def test_external_link_accessibility():
    """External links must provide context warnings for screen readers."""
    from scanner.cli.appguardrail import dashboard_index_path
    html = dashboard_index_path().read_text(encoding="utf-8")
    assert 'aria-label="${esc(r)} (opens in a new tab)"' in html
