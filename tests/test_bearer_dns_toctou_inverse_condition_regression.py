"""Control-flow compatibility regressions for Bearer DNS TOCTOU detectors."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_FAMILY = {
    "python-bearer-preflight-dns-toctou",
    "python-bearer-preflight-dns-toctou-header-mutation",
    "python-bearer-preflight-dns-toctou-multiline-constructor",
    "python-bearer-preflight-dns-toctou-multiline-header-mutation",
    "python-bearer-preflight-dns-toctou-dynamic-bearer-replacement",
    "python-bearer-preflight-dns-toctou-unredirected-header-persistence",
}


def _family_findings(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in _FAMILY
    ]


def test_inverse_boolean_guard_cannot_borrow_one_line_bearer_state(tmp_path):
    source = """\
def deliver(url, api_key, enabled):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    if enabled:
        req.add_header("Authorization", f"Bearer {api_key}")
    if not enabled:
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert _family_findings(tmp_path, source) == []


def test_inverse_boolean_guard_cannot_borrow_multiline_bearer_state(tmp_path):
    source = """\
def deliver(url, api_key, enabled):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    if enabled:
        req.add_header(
            "Authorization",
            f"Bearer {api_key}",
        )
    if not enabled:
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert _family_findings(tmp_path, source) == []


def test_guarded_bearer_mutation_still_reaches_outer_dispatch(tmp_path):
    source = """\
def deliver(url, api_key, enabled):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    if enabled:
        req.add_header("Authorization", f"Bearer {api_key}")
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [
        "python-bearer-preflight-dns-toctou-header-mutation"
    ]


def test_guarded_multiline_bearer_mutation_still_reaches_outer_dispatch(tmp_path):
    source = """\
def deliver(url, api_key, enabled):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    if enabled:
        req.add_header(
            "Authorization",
            f"Bearer {api_key}",
        )
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [
        "python-bearer-preflight-dns-toctou-multiline-header-mutation"
    ]
