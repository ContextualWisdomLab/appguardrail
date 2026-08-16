"""Regression contracts for dashboard findings-file selection."""

from pathlib import Path

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
    assert 'onclick="document.getElementById(\'file\').click()"' not in html


def test_header_upload_proxy_is_native_tokenized_and_state_perceivable() -> None:
    """The header proxy must keep its visible action text as its accessible name."""
    html = _dashboard_html()

    assert (
        '<button type="button" id="upload-btn" class="upload-action">'
        'Upload findings file</button>'
    ) in html
    assert 'id="upload-btn" class="upload-action" aria-label=' not in html
    assert "const uploadBtn = document.getElementById('upload-btn');" in html
    assert "uploadBtn.addEventListener('click', () => fileInput.click());" in html
    assert ".upload-action{" in html
    assert ".upload-action:hover{" in html
    assert ".upload-action:disabled{" in html
    assert 'id="upload-btn" style=' not in html


def test_proxy_hides_the_native_input_without_duplicate_accessible_naming() -> None:
    """Only the native proxy button should appear in the accessibility tree."""
    html = _dashboard_html()

    assert (
        '<input type="file" id="file" accept="application/json,.json" '
        'class="sr-only" tabindex="-1" aria-hidden="true">'
    ) in html
    assert 'aria-hidden="true" aria-label="Upload findings file"' not in html


def test_file_input_resets_only_after_a_selection_change() -> None:
    """Clearing after change enables same-file reloads without losing cancelled picks."""
    html = _dashboard_html()

    assert "const fileInput = document.getElementById('file');" in html
    assert "const selectedFile = fileInput.files?.[0];" in html
    assert "fileInput.value = '';" in html
    assert 'onclick="this.value=null"' not in html


def test_upload_proxy_has_release_note_fragment() -> None:
    """Buyer-visible upload behavior must remain discoverable in release notes."""
    changelog_fragment = (
        Path(__file__).resolve().parents[1]
        / "CHANGELOG.d"
        / "969-dashboard-upload-proxy.md"
    )

    assert changelog_fragment.is_file()
    text = changelog_fragment.read_text(encoding="utf-8")
    assert "Upload findings file" in text
    assert "same file" in text.lower()
