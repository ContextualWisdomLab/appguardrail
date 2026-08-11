"""Regression tests for the console connection-count status."""

from scanner.cli.appguardrail import dashboard_index_path


def _console_html() -> str:
    """Return the packaged organization console document."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def test_connection_count_is_an_atomic_polite_status_region() -> None:
    """Asynchronous scan-count updates must be announced without interrupting users."""
    html = _console_html()

    assert (
        'id="conn" role="status" aria-live="polite" aria-atomic="true"'
        in html
    )


def test_connection_count_uses_grammatical_singular_and_plural_labels() -> None:
    """The visible status must render `scan` for one item and `scans` otherwise."""
    html = _console_html()

    assert 'scans.length+" scan"+(scans.length===1?"":"s")' in html
    assert "scan(s)" not in html
