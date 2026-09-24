"""Executable contracts for dashboard finding-reference links."""

import re

from scanner.cli.appguardrail import dashboard_index_path


def _reference_template() -> str:
    """Return only the reference-link template used by ``openDetail``."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    match = re.search(
        r"const refs = \(f\.references\|\|\[\]\)\.map\(r=>(?P<template>`.*?`)\)\.join\('<br>'\);",
        html,
    )
    assert match is not None, "finding-detail reference template is missing"
    return match.group("template")


def test_external_reference_link_keeps_safe_url_and_text_escaping_boundary():
    """Untrusted reference values remain escaped in both URL and visible text."""
    template = _reference_template()

    assert 'href="${esc(safeUrl(r))}"' in template
    assert "${esc(r)}" in template
    assert 'href="${r}"' not in template
    assert ">${r}<" not in template


def test_external_reference_link_announces_new_tab_once_and_hides_glyph():
    """The new-tab behavior is explicit without duplicating decorative SVG output."""
    template = _reference_template()

    assert template.count('target="_blank"') == 1
    assert template.count('rel="noopener"') == 1
    assert template.count('(opens in a new tab)') == 1
    assert '<span class="sr-only">(opens in a new tab)</span>' in template
    assert template.count('aria-hidden="true"') == 1
