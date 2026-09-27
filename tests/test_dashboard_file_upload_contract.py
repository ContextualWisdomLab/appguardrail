"""Regression contracts for dashboard findings-file selection."""

from scanner.cli.appguardrail import dashboard_index_path


def _dashboard_html() -> str:
    """Return the shipped dashboard document as UTF-8 text."""
    return dashboard_index_path().read_text(encoding="utf-8")


def test_empty_state_browse_action_uses_an_accessible_event_listener() -> None:
    """The empty state must expose a native button without inline script handlers."""
    html = _dashboard_html()

    assert 'id="browse-findings"' in html
    assert 'aria-describedby="findings-upload-help"' in html
    assert "browseFindings.addEventListener('click'" in html
    assert "fileInput.click()" in html
    assert "onclick=\"document.getElementById('file').click()\"" not in html


def test_file_input_resets_only_after_a_selection_change() -> None:
    """Clearing after change enables same-file reloads without losing cancelled picks."""
    html = _dashboard_html()

    assert "const fileInput = document.getElementById('file');" in html
    assert "const selectedFile = fileInput.files?.[0];" in html
    assert "fileInput.value = '';" in html
    assert 'onclick="this.value=null"' not in html
