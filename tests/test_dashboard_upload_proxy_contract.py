"""Contracts for the dashboard file-upload proxy control."""

from __future__ import annotations

import re
from pathlib import Path


DASHBOARD = Path("scanner/dashboard/index.html")


def _header_upload_button(html: str) -> str:
    """Return the shipped header upload button tag."""
    match = re.search(r'<button\b[^>]*\bid="header-browse"[^>]*>', html)
    assert match is not None, "header upload proxy button must exist"
    return match.group(0)


def test_header_upload_proxy_preserves_primary_action_touch_target() -> None:
    """The header proxy must not override the shared 44px primary-action target."""
    html = DASHBOARD.read_text(encoding="utf-8")
    button = _header_upload_button(html)

    assert 'class="primary-action"' in button
    assert "min-height:auto" not in button.replace(" ", "")
    assert "padding:6px 12px" not in button


def test_header_upload_proxy_keeps_visible_name_and_native_file_boundary() -> None:
    """The visible button owns the name while the hidden native input owns selection."""
    html = DASHBOARD.read_text(encoding="utf-8")

    assert ">Upload findings file</button>" in html
    assert '<input type="file" id="file" accept="application/json,.json" hidden>' in html
    assert "document.getElementById('header-browse').addEventListener('click', () => fileInput.click())" in html
    # Same-file re-selection is enabled by clearing the native input after handling it;
    # it is not a property of the proxy button itself.
    assert "fileInput.value = '';" in html
