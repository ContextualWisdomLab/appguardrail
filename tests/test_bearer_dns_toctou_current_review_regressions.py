"""Current-head flow-boundary regressions for bearer DNS TOCTOU detection."""

from scanner.cli.appguardrail import _scan_file

_RULE_ID = "python-bearer-preflight-dns-toctou"


def _scan_source(tmp_path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def _bearer_source(request_url: str = "endpoint", dispatch: str = "return urllib.request.urlopen(req, timeout=5)") -> str:
    return f'''\
def deliver(url, api_key, enabled=True):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        {request_url},
        headers={{"Authorization": f"Bearer {{api_key}}"}},
    )
    {dispatch}
'''


def test_keyword_url_bearer_request_is_detected(tmp_path):
    """`Request(url=endpoint, ...)` retains the same vulnerable destination flow."""
    assert len(_scan_source(tmp_path, _bearer_source("url=endpoint"))) == 1


def test_conditional_urlopen_dispatch_is_detected(tmp_path):
    """A nested conditional dispatch remains an executable vulnerable path."""
    source = _bearer_source(
        dispatch="if enabled:\n        return urllib.request.urlopen(req, timeout=5)"
    )
    assert len(_scan_source(tmp_path, source)) == 1


def test_unauthenticated_request_rebuild_breaks_bearer_provenance(tmp_path):
    """Rebuilding the request without Authorization must not inherit stale credentials."""
    source = _bearer_source(
        dispatch="req = urllib.request.Request(endpoint)\n    return urllib.request.urlopen(req, timeout=5)"
    )
    assert not _scan_source(tmp_path, source)


def test_remove_authorization_header_breaks_bearer_provenance(tmp_path):
    """A supported explicit Authorization removal must suppress stale bearer evidence."""
    source = _bearer_source(
        dispatch='req.remove_header("Authorization")\n    return urllib.request.urlopen(req, timeout=5)'
    )
    assert not _scan_source(tmp_path, source)


def test_pop_authorization_header_breaks_bearer_provenance(tmp_path):
    """Removing Authorization from the request header mapping breaks credential flow."""
    source = _bearer_source(
        dispatch='req.headers.pop("Authorization", None)\n    return urllib.request.urlopen(req, timeout=5)'
    )
    assert not _scan_source(tmp_path, source)


def test_delete_authorization_header_breaks_bearer_provenance(tmp_path):
    """Deleting Authorization before dispatch is another explicit credential barrier."""
    source = _bearer_source(
        dispatch='del req.headers["Authorization"]\n    return urllib.request.urlopen(req, timeout=5)'
    )
    assert not _scan_source(tmp_path, source)
