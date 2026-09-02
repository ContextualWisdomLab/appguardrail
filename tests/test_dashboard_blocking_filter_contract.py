"""Contracts for the deploy-blocking dashboard filter."""

import re

from scanner.cli.appguardrail import dashboard_index_path


def _dashboard_html() -> str:
    """Read the shipped dashboard asset used by the CLI server."""
    return dashboard_index_path().read_text(encoding="utf-8")


def test_deploy_blocking_card_filter_contract_is_complete() -> None:
    """The card must toggle the real blocking predicate and expose pressed state."""
    html = _dashboard_html()
    card = re.search(
        r'<div id="deploy-blocking-card" class="card"(?P<attrs>[^>]*)>',
        html,
    )

    assert card is not None
    attrs = card.group("attrs")
    assert 'role="button"' in attrs
    assert 'tabindex="0"' in attrs
    assert 'aria-pressed="${filterBlocking}"' in attrs
    assert 'onclick="filterBlocking=!filterBlocking; render();"' in attrs
    assert "event.key==='Enter'||event.key===' '" in attrs
    assert ".filter(({f})=> !filterBlocking || isDeployBlocking(f))" in html


def test_deploy_blocking_card_keeps_focus_across_render() -> None:
    """Replacing dashboard markup must restore focus to the toggled card."""
    html = _dashboard_html()

    assert "const activeId = activeElement?.id || null;" in html
    assert "const restoredElement = activeId ? document.getElementById(activeId) : null;" in html
    assert "restoredElement.focus();" in html
    assert 'id="deploy-blocking-card"' in html
