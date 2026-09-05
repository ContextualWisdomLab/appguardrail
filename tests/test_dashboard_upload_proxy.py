"""Regression contracts for the dashboard findings upload proxy."""

from scanner.cli.appguardrail import dashboard_index_path


def _dashboard_html() -> str:
    """Return the shipped dashboard asset used by the static server."""
    return dashboard_index_path().read_text(encoding="utf-8")


def test_upload_proxy_keeps_one_accessible_visible_trigger():
    """Expose one visible native button while keeping the picker input hidden."""
    html = _dashboard_html()

    assert '<button id="upload-proxy" class="primary-action"' in html
    assert '>Upload findings file</button>' in html
    assert '<input type="file" id="file" accept="application/json,.json" hidden>' in html
    assert "document.getElementById('upload-proxy').addEventListener('click', () => fileInput.click())" in html


def test_upload_proxy_preserves_cancel_and_same_file_reselection_contract():
    """Capture the File before clearing the input and keep cancellation harmless."""
    html = _dashboard_html()

    capture = "const selectedFile = fileInput.files?.[0];"
    clear = "fileInput.value = '';"
    cancel_guard = "if(!selectedFile) return;"
    load = "load(JSON.parse(t), selectedFile.name)"

    assert html.index(capture) < html.index(clear) < html.index(cancel_guard)
    assert load in html
    assert "alert('Invalid JSON: '+err.message)" in html
