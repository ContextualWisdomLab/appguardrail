"""Current-head regression boundaries for constructor-supplied Bearer DNS TOCTOU."""

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


def test_mixed_case_constructor_bearer_reaches_primary_rule(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, headers={"authorization": f"bEaReR {api_key}"})
    return urllib.request.urlopen(req)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]


def test_primary_keyword_urlopen_dispatch_is_detected(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {api_key}"})
    return urllib.request.urlopen(url=req)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]


def test_primary_keyword_reviewed_opener_dispatch_is_detected(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {api_key}"})
    opener = urllib.request.build_opener(SafeRedirectHandler())
    return opener.open(fullurl=req)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]


def test_static_non_bearer_overwrite_kills_primary_credential_state(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {api_key}"})
    req.headers["Authorization"] = "Basic fixed"
    return urllib.request.urlopen(req)
"""
    assert not _family_findings(tmp_path, source)


def test_static_non_bearer_add_header_kills_primary_credential_state(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {api_key}"})
    req.add_header("Authorization", "Basic fixed")
    return urllib.request.urlopen(req)
"""
    assert not _family_findings(tmp_path, source)


def test_later_bearer_update_preserves_primary_credential_state(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {api_key}"})
    req.headers["Authorization"] = f"Bearer {api_key}"
    return urllib.request.urlopen(req)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]
