"""Regression tests for asynchronous console detail rendering."""

from pathlib import Path

from scanner.cli.appguardrail import dashboard_index_path

ROOT = Path(__file__).resolve().parents[1]


def _console_html() -> str:
    """Return the standalone console document as UTF-8 text."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def _css_declaration(html: str, selector: str) -> str:
    """Return the CSS declaration block for an exact selector string."""
    token = selector + "{"
    start = html.index(token) + len(token)
    return html[start : html.index("}", start)]


def test_console_ignores_out_of_order_detail_results_and_errors():
    """Only the most recently selected scan may update the shared detail panel."""
    html = _console_html()

    assert "let currentDetailRequest=0;" in html
    assert "const requestId=++currentDetailRequest;" in html
    assert html.count("if(requestId!==currentDetailRequest)return;") == 2
    assert "tr.dataset.detailRequest=String(requestId);" in html
    assert "tr.dataset.detailRequest===String(requestId)" in html


def test_console_exposes_loading_busy_and_error_states():
    """Busy and unavailable semantics must stay distinct and keyboard-consistent."""
    html = _console_html()

    assert "--busy-opacity:.6;" in html
    assert ':disabled, [aria-busy="true"]' not in html
    unavailable = _css_declaration(
        html, 'button:disabled, tr.scan[aria-disabled="true"]'
    )
    busy = _css_declaration(
        html, '#connect[aria-busy="true"], tr.scan[aria-busy="true"]'
    )
    assert "opacity:var(--busy-opacity)" in unavailable
    assert "pointer-events:none" in unavailable
    assert "opacity:var(--busy-opacity)" in busy
    assert "pointer-events" not in busy
    assert 'tr.setAttribute("aria-busy","true");' in html
    assert 'tr.setAttribute("aria-disabled","true");' in html
    assert 'if(tr&&tr.getAttribute("aria-disabled")==="true")return;' in html
    assert 'aria-live="polite" class="muted">Loading scan details...' in html
    assert 'role="alert" class="err">Error loading details:' in html
    assert 'tr.removeAttribute("aria-busy");' in html
    assert 'tr.removeAttribute("aria-disabled");' in html


def test_console_busy_state_docs_name_the_next_reusable_surface():
    """Buyers and later Storybook work must find the token contract without reading CSS."""
    inventory = (ROOT / "docs" / "storybook-inventory.md").read_text(encoding="utf-8")
    changelog = (
        ROOT / "CHANGELOG.d" / "974-console-busy-unavailable.md"
    ).read_text(encoding="utf-8")
    adr = (
        ROOT / "docs" / "adr" / "0007-console-busy-unavailable-tokens.md"
    ).read_text(encoding="utf-8")

    assert "--busy-opacity" in inventory
    assert "ScanRow/BusyUnavailable" in inventory
    assert "pointer-events: none" in inventory
    assert "aria-disabled" in changelog
    assert "WAI-ARIA" in adr
    assert "https://www.w3.org/TR/wai-aria-1.2/" in adr


def test_console_detail_scrolling_respects_reduced_motion():
    """Successful and failed detail requests must honor reduced-motion preferences."""
    html = _console_html()

    assert 'window.matchMedia("(prefers-reduced-motion: reduce)").matches' in html
    assert "element.scrollIntoView();" in html
    assert 'element.scrollIntoView({behavior:"smooth"});' in html
    assert html.count("scrollDetailIntoView(d);") == 2
