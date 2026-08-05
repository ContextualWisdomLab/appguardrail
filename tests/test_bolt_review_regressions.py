"""Regression contracts for reviewed scanner hot-path and redirect changes."""

from __future__ import annotations

import inspect
import urllib.error
import urllib.request

import pytest

from appguardrail_core.controlplane import SafeRedirectHandler
from appguardrail_core.language import detect_language_axes
from scanner.cli import appguardrail as cli


class StringPath(str):
    """A string subtype accepted by public path APIs."""


def _redirect_copy(_self, request, _fp, _code, _msg, _headers, new_url):
    """Return a redirected request that initially copies every source header."""
    return urllib.request.Request(new_url, headers=dict(request.header_items()))


def test_string_subclass_uses_string_path_contract() -> None:
    """String subclasses must not be treated as pathlib objects."""
    path = StringPath(r"src\service.py")

    assert detect_language_axes([path]) == {"python"}
    assert cli._display_path(path) == "src/service.py"


def test_push_rejects_public_http_before_network(monkeypatch, capsys) -> None:
    """Bearer credentials are never sent over a cleartext public URL."""
    monkeypatch.setenv("APPGUARDRAIL_API_KEY", "secret")

    def fail_network(*_args, **_kwargs):
        raise AssertionError("network must not be reached")

    monkeypatch.setattr(urllib.request, "build_opener", fail_network)
    cli._push_findings("http://example.com", [])

    assert "public HTTPS URL" in capsys.readouterr().err


def test_cross_origin_redirect_removes_sensitive_headers(monkeypatch) -> None:
    """A public cross-origin redirect cannot inherit bearer credentials."""
    monkeypatch.setattr(
        urllib.request.HTTPRedirectHandler, "redirect_request", _redirect_copy
    )
    request = urllib.request.Request(
        "https://api.example.com/scans",
        headers={
            "Authorization": "Bearer secret",
            "Proxy-Authorization": "Basic secret",
        },
    )

    redirected = SafeRedirectHandler().redirect_request(
        request, None, 302, "Found", {}, "https://collector.example.net/next"
    )

    assert redirected is not None
    assert redirected.get_header("Authorization") is None
    assert redirected.get_header("Proxy-Authorization") is None


def test_same_origin_https_redirect_preserves_authorization(monkeypatch) -> None:
    """A same-origin HTTPS redirect retains its scoped bearer credential."""
    monkeypatch.setattr(
        urllib.request.HTTPRedirectHandler, "redirect_request", _redirect_copy
    )
    request = urllib.request.Request(
        "https://api.example.com/scans",
        headers={"Authorization": "Bearer secret"},
    )

    redirected = SafeRedirectHandler().redirect_request(
        request, None, 302, "Found", {}, "https://api.example.com/next"
    )

    assert redirected is not None
    assert redirected.get_header("Authorization") == "Bearer secret"


def test_authenticated_redirect_rejects_https_downgrade(monkeypatch) -> None:
    """Authenticated redirects cannot downgrade transport security."""
    monkeypatch.setattr(
        urllib.request.HTTPRedirectHandler, "redirect_request", _redirect_copy
    )
    request = urllib.request.Request(
        "https://api.example.com/scans",
        headers={"Authorization": "Bearer secret"},
    )

    with pytest.raises(urllib.error.URLError, match="require HTTPS"):
        SafeRedirectHandler().redirect_request(
            request, None, 302, "Found", {}, "http://example.com/next"
        )


def test_scan_file_has_one_direct_caller_fallback_stat() -> None:
    """The root file check exists only in the standalone-call fallback."""
    source = inspect.getsource(cli._scan_file)

    assert source.count("base_path.is_file()") == 1
    assert "if base_path_is_file" in source
