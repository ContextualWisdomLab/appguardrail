"""Regression tests for the dashboard's global search shortcut."""

from scanner.cli.appguardrail import dashboard_index_path


def test_search_shortcut_is_discoverable_and_declared_to_assistive_technology() -> None:
    """The search control must expose both a visible hint and ARIA shortcut metadata."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert 'title="Press / to search"' in html
    assert 'aria-keyshortcuts="/"' in html


def test_search_shortcut_does_not_hijack_handled_or_editable_keystrokes() -> None:
    """The global slash key must respect modifiers, prior handlers, and editable targets."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert "e.defaultPrevented" in html
    assert "!e.ctrlKey && !e.metaKey && !e.altKey" in html
    assert "isContentEditable" in html
    assert "INPUT" in html.upper()
    assert "TEXTAREA" in html.upper()
    assert "SELECT" in html.upper()
