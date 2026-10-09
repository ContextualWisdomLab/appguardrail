"""Accessibility contract for the deploy-blocking dashboard filter."""

from scanner.cli.appguardrail import dashboard_index_path


def test_deploy_blocking_filter_uses_native_button_semantics() -> None:
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert '<button type="button" class="card"' in html
    assert 'aria-pressed="${filterBlocking}"' in html
    # The regression test wants to ensure Deploy-blocking doesn't use the manual div role pattern
    assert (
        '<div class="card" role="button" tabindex="0" aria-label="Filter by deploy-blocking'
        not in html
    )
