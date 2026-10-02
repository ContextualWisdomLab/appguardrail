"""Tests for the `appguardrail dashboard` static server."""

import json
import json as _json
import re
import threading
import urllib.error
import urllib.request
from contextlib import closing
from html.parser import HTMLParser

import pytest

from scanner.cli.appguardrail import (dashboard_index_path,
                                      dashboard_tokens_path,
                                      make_dashboard_server, render_tokens_css)


class _ButtonAttributeParser(HTMLParser):
    """Collect attributes from every dashboard button element."""

    def __init__(self):
        """Initialize an empty button-attribute collection."""
        super().__init__()
        self.buttons = []

    def handle_starttag(self, tag, attrs):
        """Record one button's attributes while ignoring other elements."""
        if tag == "button":
            self.buttons.append(dict(attrs))


def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _get(url):
    with closing(urllib.request.urlopen(url, timeout=5)) as resp:
        return resp.status, resp.read()


def test_dashboard_index_ships_with_repo():
    index = dashboard_index_path()
    assert index.is_file(), f"dashboard asset missing: {index}"
    assert b"AppGuardrail" in index.read_bytes()


def test_dashboard_skip_link_is_first_and_targets_focusable_main():
    """Keyboard users can bypass repeated controls and focus the main region."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    skip_link = '<a href="#app" class="skip-link">Skip to content</a>'
    assert skip_link in html
    assert '<main id="app" tabindex="-1">' in html
    assert html.index(skip_link) < html.index("<header>")
    assert ".skip-link:focus" in html
    assert "outline:3px solid #fff" in html


def test_dashboard_drag_drop_has_visible_state_and_clears_it():
    """Drag-and-drop exposes feedback and always clears it after leaving or dropping."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert "body.drag-active::after" in html
    assert 'document.body.classList.add("drag-active")' in html
    assert 'document.body.classList.remove("drag-active")' in html
    assert "addEventListener(\"dragenter\"" in html
    assert "addEventListener(\"dragleave\"" in html
    assert "addEventListener(\"drop\"" in html


def test_dashboard_rows_are_keyboard_accessible():
    """Interactive finding rows must expose keyboard and screen-reader affordances."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert 'tabindex="0" role="button"' in html
    assert 'title="View details for finding"' in html
    assert "tbody tr:focus-visible" in html
    assert "aria-label=\"Upload findings file\"" in html
    assert "aria-label=\"Search findings\"" in html
    assert "aria-label=\"Filter by severity\"" in html
    assert "tr.addEventListener('keydown'" in html
    assert "e.key === 'Enter' || e.key === ' '" in html


def test_dashboard_severity_cards_are_accessible_filter_toggles():
    """Severity cards must preserve their complete pointer and keyboard contract."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert 'aria-label="Filter by ${s}: ${counts[s]}"' in html
    assert 'aria-pressed="${isSelected}"' in html
    assert "document.getElementById('sev').value='${isSelected ? '' : s}'" in html
    assert "dispatchEvent(new Event('change'))" in html
    assert (
        'onkeydown="if(event.key===\'Enter\'||event.key===\' \')'
        '{event.preventDefault(); this.click();}"' in html
    )


def test_dashboard_escapes_severity_in_innerhtml():
    """Severity chips must go through esc() — findings JSON is untrusted input."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    # Row template and detail dialog both interpolate severity into innerHTML.
    assert html.count("${esc(s)}") >= 2
    assert "${s}</span>" not in html


def test_server_serves_index_and_findings(tmp_path):
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps(
            {"schema": "appguardrail.findings.v1", "findings": [{"rule_id": "x"}]}
        )
    )
    server = make_dashboard_server("127.0.0.1", 0, b"<html>DASH</html>", findings)
    port = server.server_address[1]
    _serve(server)
    try:
        status, body = _get(f"http://127.0.0.1:{port}/")
        assert status == 200 and b"DASH" in body

        status, body = _get(f"http://127.0.0.1:{port}/findings.json")
        assert status == 200
        assert json.loads(body)["findings"][0]["rule_id"] == "x"
    finally:
        server.shutdown()
        server.server_close()


def test_design_tokens_source_is_valid():
    path = dashboard_tokens_path()
    assert path.is_file(), f"design token source missing: {path}"
    data = _json.loads(path.read_text())
    # canonical color tokens the dashboard and Figma library depend on
    for key in (
        "background",
        "surface",
        "text-default",
        "primary",
        "critical",
        "high",
        "warning",
        "info",
    ):
        assert key in data["color"], f"missing color token: {key}"
        assert data["color"][key]["value"].startswith("#")


def test_render_tokens_css_emits_dashboard_vars():
    css = render_tokens_css(_json.loads(dashboard_tokens_path().read_text()))
    assert css.startswith(":root{")
    # the exact CSS custom properties the stylesheet consumes
    for var in ("--primary", "--crit", "--surface", "--text", "--radius"):
        assert var in css
    # value passthrough
    assert "#256EF4" in css  # primary


def _norm_color(v):
    v = v.strip().lower()
    if v.startswith("#") and len(v) == 4:  # #abc -> #aabbcc
        v = "#" + "".join(c * 2 for c in v[1:])
    return v


def _parse_root_vars(css_text):
    root = css_text[css_text.index(":root{") + len(":root{") :]
    root = root[: root.index("}")]
    return {
        m.group(1): _norm_color(m.group(2))
        for m in __import__("re").finditer(r"--([\w-]+)\s*:\s*([^;]+);", root)
    }


def test_inline_fallback_matches_token_source():
    """Every var in the index.html fallback must match tokens.json (no drift).

    Direction is fallback ⊆ source: the served tokens.css may expose more
    (full scales); the inline fallback only needs the vars the page consumes,
    and each must equal the canonical value.
    """
    html = dashboard_index_path().read_text()
    fallback = _parse_root_vars(html)
    source = _parse_root_vars(
        render_tokens_css(_json.loads(dashboard_tokens_path().read_text()))
    )
    for var, val in fallback.items():
        assert var in source, f"fallback var {var} not in tokens.json source"
        assert (
            source[var] == val
        ), f"{var} drift: fallback {val} != tokens.json {source[var]}"


def test_tokens_include_full_scales():
    data = _json.loads(dashboard_tokens_path().read_text())
    # radius scale sourced from Figma
    for k, v in {
        "none": "0",
        "sm": "4px",
        "md": "8px",
        "lg": "12px",
        "xl": "16px",
    }.items():
        assert data["radius"][k]["value"] == v
    # spacing scale
    for k in ("0", "4", "8", "16", "24", "64"):
        assert k in data["space"]
    # sizes incl. WCAG touch target
    assert data["size"]["touch-target"]["value"] == "44px"


def test_render_tokens_css_emits_scales():
    css = render_tokens_css(_json.loads(dashboard_tokens_path().read_text()))
    for var in ("--radius-md", "--radius-full", "--space-16", "--size-touch-target"):
        assert var in css, f"missing scale var {var}"
    # --radius alias resolves to the card-alias (lg = 12px)
    assert "--radius: 12px;" in css


def test_tokens_include_high_contrast_mode():
    data = _json.loads(dashboard_tokens_path().read_text())
    hc = data["high-contrast"]
    # HC must override the key state colors with maximal-contrast values
    assert hc["text-default"]["value"] == "#000000"
    assert hc["border"]["value"] == "#000000"
    assert hc["primary"]["value"].startswith("#")


def test_render_tokens_css_emits_high_contrast_media_query():
    css = render_tokens_css(_json.loads(dashboard_tokens_path().read_text()))
    assert "@media (prefers-contrast: more)" in css
    # HC primary value present inside the media block
    assert "#0038A8" in css
    # base still first
    assert css.index(":root{") < css.index("@media")


def test_server_serves_tokens_css(tmp_path):
    findings = tmp_path / "f.json"
    findings.write_text('{"findings":[]}')
    css = b":root{--primary:#256EF4;}"
    server = make_dashboard_server("127.0.0.1", 0, b"<html>DASH</html>", findings, css)
    port = server.server_address[1]
    _serve(server)
    try:
        status, body = _get(f"http://127.0.0.1:{port}/tokens.css")
        assert status == 200 and b"--primary" in body
    finally:
        server.shutdown()
        server.server_close()


def test_server_404s_missing_findings(tmp_path):
    missing = tmp_path / "nope.json"
    server = make_dashboard_server("127.0.0.1", 0, b"<html>DASH</html>", missing)
    port = server.server_address[1]
    _serve(server)
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(f"http://127.0.0.1:{port}/findings.json")
        assert exc.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_empty_state_clear_filters():
    """Empty state CTA must expose Clear filters control that resets state."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert "No findings match the filter" in html
    assert "aria-label=\"Clear filters\"" in html
    assert "onclick=\"query=''; filterSev=''; render(); document.getElementById('q')?.focus();\"" in html
    assert "Clear filters</button>" in html


def test_dashboard_dialog_close_button_has_tooltip():
    """The dynamically rendered close button exposes its label and Esc tooltip."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    detail_markup = re.search(
        r"d\.innerHTML\s*=\s*`(?P<markup>.*?)`;",
        html,
        flags=re.DOTALL,
    )
    assert detail_markup is not None

    parser = _ButtonAttributeParser()
    parser.feed(detail_markup.group("markup"))

    assert any(
        attributes.get("title") == "Close (Esc)"
        and attributes.get("aria-label") == "Close"
        for attributes in parser.buttons
    )


def test_dashboard_search_escape_clears_input():
    """Search input must expose an Escape keybind to quickly clear filters."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    assert "document.getElementById('q').addEventListener('keydown'" in html
    assert "e.key === 'Escape'" in html
    assert "query = '';" in html
    assert "render();" in html

from pathlib import Path
def test_dashboard_console_and_index_prototype_pollution_fallback(tmp_path):
    import re
    # Test console.html for explicit Object.hasOwn and esc
    console_html = (Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html").read_text(encoding="utf-8")
    assert "Object.hasOwn(SEV," in console_html
    assert "${esc(SEV[sevKey] || 'var(--info)')}" in console_html or "${esc(SEV[sevKey]||'var(--info)')}" in console_html.replace(" ", "")

    # Test index.html for explicit Object.hasOwn and esc with explicit fallback
    index_html = (Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "index.html").read_text(encoding="utf-8")
    assert "Object.hasOwn(SEV, s) ? s : 'INFO'" in index_html
    assert "${esc(SEV[sevKey] ? SEV[sevKey].color : 'var(--info)')}" in index_html

def test_dashboard_hostile_prototype_rendering(tmp_path):
    import json
    import threading
    from http.server import HTTPServer, SimpleHTTPRequestHandler
    from contextlib import closing
    from playwright.sync_api import sync_playwright

    hostile_findings = {
        "schema": "appguardrail.findings.v1",
        "findings": [
            {
                "rule_id": "r1",
                "severity": "__proto__",
                "message": "pollute prototype",
                "file": "a.py",
                "line": 1,
                "category": "sec"
            },
            {
                "rule_id": "r2",
                "severity": "constructor",
                "message": "pollute constructor",
                "file": "b.py",
                "line": 2,
                "category": "constructor"
            },
            {
                "rule_id": "r3",
                "severity": "unknown_sev",
                "message": "fallback test",
                "file": "c.py",
                "line": 3,
                "category": "unknown"
            }
        ]
    }

    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(hostile_findings))

    index_html = (Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "index.html").read_bytes()
    server = make_dashboard_server("127.0.0.1", 0, index_html, findings_file)
    port = server.server_address[1]
    thread = _serve(server)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            page.goto(f"http://127.0.0.1:{port}/")
            page.wait_for_timeout(500)

            # Check rendering and fallback properties
            html_content = page.content()

            # The prototype pollution inputs should not break the UI rendering or execute functions
            assert "pollute prototype" in html_content
            assert "pollute constructor" in html_content
            assert "fallback test" in html_content

            # Ensure no CSS values reflect '[object Object]' or native code
            assert "background:[object Object]" not in html_content
            assert "function Object() { [native code] }" not in html_content

            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
