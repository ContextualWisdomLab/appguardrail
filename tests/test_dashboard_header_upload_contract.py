"""Contracts for the dashboard header upload proxy."""

import re

from scanner.cli.appguardrail import dashboard_index_path


def _dashboard_html() -> str:
    return dashboard_index_path().read_text(encoding="utf-8")


def _header(html: str) -> str:
    match = re.search(r"<header>(?P<header>.*?)</header>", html, re.DOTALL)
    assert match is not None, "dashboard header is missing"
    return match.group("header")


def test_header_exposes_one_visible_upload_action_and_keeps_design_target_size():
    """The proxy is the user-facing control and must not shrink the shared action target."""
    header = _header(_dashboard_html())

    assert '<button type="button" id="header-browse-findings" class="primary-action"' in header
    assert ">Upload findings</button>" in header
    assert "min-height: unset" not in header
    assert "padding: 4px 12px" not in header


def test_proxy_file_input_is_an_implementation_detail_not_a_second_accessible_control():
    """A button proxy should not leave a second visually-hidden file control exposed to AT."""
    header = _header(_dashboard_html())
    file_input = re.search(r'<input type="file" id="file"[^>]*>', header)

    assert file_input is not None
    markup = file_input.group(0)
    assert " hidden" in markup
    assert 'class="sr-only"' not in markup
    assert 'tabindex="-1"' not in markup
    assert 'aria-label="Upload findings file"' not in markup


def test_header_button_proxies_to_the_existing_file_input_without_inline_handler():
    """The native button forwards its trusted activation to the existing upload boundary."""
    html = _dashboard_html()

    assert "const headerBrowseFindings = document.getElementById('header-browse-findings');" in html
    assert "const headerFileInput = document.getElementById('file');" in html
    assert "headerBrowseFindings.addEventListener('click', () => headerFileInput.click());" in html
    assert 'onclick="' not in _header(html)
