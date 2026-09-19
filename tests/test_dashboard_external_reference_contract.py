"""Regression contract for external references in the static dashboard."""

from scanner.cli.appguardrail import dashboard_index_path


def test_external_reference_link_discloses_new_context_without_inline_layout() -> None:
    """Reference links expose stable semantics without embedding presentation styles."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert '.external-reference{' in html
    assert 'class="external-reference"' in html
    assert 'target="_blank" rel="noopener noreferrer"' in html
    assert '<span class="sr-only">(opens in a new tab)</span>' in html
    assert 'aria-hidden="true" focusable="false"' in html
    assert 'target="_blank" rel="noopener" style=' not in html
