"""Accessibility and state contracts for the static AppGuardrail dashboard."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from scanner.cli.appguardrail import dashboard_index_path


class _ElementAttributeParser(HTMLParser):
    """Collect start-tag attributes keyed by element identifier."""

    def __init__(self) -> None:
        """Initialize an empty element-attribute index."""
        super().__init__()
        self.elements_by_id: dict[str, dict[str, str | None]] = {}
        self.status_region_ids: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        """Record identified elements and explicit status regions."""
        del tag
        attributes = dict(attrs)
        element_id = attributes.get("id")
        if element_id is not None:
            self.elements_by_id[element_id] = attributes
        if attributes.get("role") == "status":
            self.status_region_ids.append(element_id or "")


def _dashboard_html() -> str:
    """Return the shipped dashboard source as UTF-8 text."""
    return dashboard_index_path().read_text(encoding="utf-8")


def test_dashboard_uses_one_polite_atomic_status_region() -> None:
    """Dynamic findings state is announced once rather than by duplicate regions."""
    parser = _ElementAttributeParser()
    parser.feed(_dashboard_html())

    assert parser.status_region_ids == ["findings-summary"]
    assert parser.elements_by_id["findings-summary"] == {
        "id": "findings-summary",
        "class": "sr-only",
        "role": "status",
        "aria-live": "polite",
        "aria-atomic": "true",
    }
    assert "role" not in parser.elements_by_id["src"]
    assert "aria-live" not in parser.elements_by_id["src"]
    assert "aria-atomic" not in parser.elements_by_id["src"]


def test_dashboard_centralizes_finding_count_pluralization() -> None:
    """Every visible count uses one singular/plural formatter."""
    html = _dashboard_html()

    assert "function formatFindingCount(count)" in html
    assert "return `${count} ${count === 1 ? 'finding' : 'findings'}`;" in html
    assert "formatFindingCount(ALL.length)" in html
    assert "formatFindingCount(findings.length)" in html
    assert html.count("? 'finding' : 'findings'") == 1


def test_dashboard_escapes_double_quotes_with_complete_html_entity() -> None:
    """Attribute-sensitive quote escaping retains the entity terminator."""
    html = _dashboard_html()

    expected_mapping = (
        "{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'," "\"'\":'&#39;','`':'&#96;'}"
    )
    assert expected_mapping in html


def test_dashboard_distinguishes_unloaded_and_clean_scan_states() -> None:
    """A successfully loaded zero-finding report is not shown as missing data."""
    html = _dashboard_html()

    unloaded = html.index("if(!ALL){")
    clean = html.index("if(ALL.length === 0){")
    populated = html.index("const counts = {CRITICAL:0,HIGH:0,WARNING:0,INFO:0};")

    assert unloaded < clean < populated
    assert "<h1>Clean scan</h1>" in html
    assert "No findings were detected in this report. The deploy gate is clear." in html
    assert "Clean scan · 0 findings · deploy gate clear" in html
    assert "Load a different <code>findings.json</code> file" in html
    assert "🎉 Clean Scan" not in html


class _AnchorAttributeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.anchor_attrs: dict[str, str | None] = {}

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag == "a":
            self.anchor_attrs = dict(attrs)


def test_dashboard_external_links_warn_screen_readers() -> None:
    """External links opening in new tabs must have accessible labels warning of context switch."""
    html = _dashboard_html()

    # Extract the literal anchor tag from the JS code
    match = re.search(
        r"const refs = [^`]+`(<a[^>]+>)\$\{esc\(r\)\}</a>`", html, re.DOTALL
    )
    assert match is not None
    anchor_html = match.group(1) + "</a>"

    parser = _AnchorAttributeParser()
    parser.feed(anchor_html)

    assert parser.anchor_attrs.get("target") == "_blank"
    assert parser.anchor_attrs.get("aria-label") == "${esc(r)} (opens in a new tab)"
