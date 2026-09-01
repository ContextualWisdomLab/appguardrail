"""Flow-boundary regressions for bearer-authenticated DNS TOCTOU detection."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-bearer-preflight-dns-toctou"


def _scan_source(tmp_path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def _prefix() -> str:
    return """\
def push_scan(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
"""


def test_packaged_bearer_dns_toctou_rule_is_loaded():
    assert sum(rule["id"] == _RULE_ID for rule in SCAN_RULES) == 1


def test_assigned_urlopen_dispatch_is_detected(tmp_path):
    source = _prefix() + """\
    response = urllib.request.urlopen(
        req,
    )
    return response
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_assigned_reviewed_opener_dispatch_is_detected(tmp_path):
    source = _prefix() + """\
    opener = urllib.request.build_opener(SafeRedirectHandler())
    response = opener.open(
        req,
    )
    return response
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_unreachable_sink_after_body_return_is_not_flagged(tmp_path):
    source = _prefix() + """\
    return None
    response = urllib.request.urlopen(req)
"""
    assert not _scan_source(tmp_path, source)


def test_reassigned_request_before_dispatch_is_not_flagged(tmp_path):
    source = _prefix() + """\
    req = object()
    response = urllib.request.urlopen(req)
    return response
"""
    assert not _scan_source(tmp_path, source)


def test_reassigned_endpoint_before_request_is_not_flagged(tmp_path):
    source = """\
def push_scan(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    endpoint = "https://example.com/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req)
"""
    assert not _scan_source(tmp_path, source)
