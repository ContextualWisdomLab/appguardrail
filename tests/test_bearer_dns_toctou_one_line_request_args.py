"""One-line Request argument-order regressions for Bearer DNS TOCTOU detection."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_PRIMARY = "python-bearer-preflight-dns-toctou"
_MUTATION = "python-bearer-preflight-dns-toctou-header-mutation"
_FAMILY = {_PRIMARY, _MUTATION}


def _family_findings(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in _FAMILY
    ]


def test_one_line_request_with_data_and_method_before_headers_is_detected(tmp_path):
    source = """\
def deliver(url, payload, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, data=payload, method="POST", headers={"Authorization": f"Bearer {api_key}"})
    return urllib.request.urlopen(req, timeout=5)
"""

    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]


def test_nested_headers_inside_data_are_not_request_header_evidence(tmp_path):
    source = """\
def deliver(url, payload, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, data=encode(headers={"Authorization": f"Bearer {api_key}"}))
    return urllib.request.urlopen(req, timeout=5)
"""

    assert _family_findings(tmp_path, source) == []
