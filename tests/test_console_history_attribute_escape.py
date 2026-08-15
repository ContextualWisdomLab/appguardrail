"""Regression tests for scan-history attribute escaping in the browser console."""

from scanner.cli.appguardrail import dashboard_index_path


def test_scan_history_identifier_is_escaped_before_attribute_rendering() -> None:
    """Scan identifiers must not be able to break out of the row data attribute."""
    html = dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")
    history_template = html.split('$("#history tbody").innerHTML=', 1)[1].split(
        'document.querySelectorAll("tr.scan")', 1
    )[0]

    assert 'data-id="${esc(s.id)}"' in history_template
    assert 'data-id="${s.id}"' not in history_template
