"""Accessibility contract for dashboard links that open a new browser tab."""

from pathlib import Path


_DASHBOARD = Path("scanner/dashboard/index.html")


def test_external_reference_link_warns_visually_and_in_accessible_name() -> None:
    """New-tab references keep the visible URL and expose a perceivable context hint."""
    source = _DASHBOARD.read_text(encoding="utf-8")

    assert 'target="_blank" rel="noopener"' in source
    assert 'aria-label="${esc(r)} (opens in a new tab)"' not in source
    assert (
        '${esc(r)} <span aria-hidden="true">↗</span>'
        '<span class="sr-only"> (opens in a new tab)</span></a>'
    ) in source
