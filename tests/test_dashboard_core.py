"""Tests for the `appguardrail dashboard` static server."""

import json
import threading
import urllib.error
import urllib.request
from contextlib import closing

import pytest

import json as _json

from scanner.cli.appguardrail import (
    dashboard_index_path,
    dashboard_tokens_path,
    make_dashboard_server,
    render_tokens_css,
)


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


def test_server_serves_index_and_findings(tmp_path):
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps({"schema": "appguardrail.findings.v1", "findings": [{"rule_id": "x"}]})
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
    for key in ("background", "surface", "text-default", "primary", "critical", "high", "warning", "info"):
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
    root = css_text[css_text.index(":root{") + len(":root{"):]
    root = root[: root.index("}")]
    return {
        m.group(1): _norm_color(m.group(2))
        for m in __import__("re").finditer(r"--([\w-]+)\s*:\s*([^;]+);", root)
    }


def test_inline_fallback_matches_token_source():
    """The hardcoded :root fallback in index.html must not drift from tokens.json."""
    html = dashboard_index_path().read_text()
    fallback = _parse_root_vars(html)
    source = _parse_root_vars(
        render_tokens_css(_json.loads(dashboard_tokens_path().read_text()))
    )
    for var, val in source.items():
        assert var in fallback, f"fallback missing {var}"
        assert fallback[var] == val, f"{var} drift: fallback {fallback[var]} != tokens.json {val}"


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
