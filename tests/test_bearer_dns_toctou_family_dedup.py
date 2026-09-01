"""Family-level regression boundaries for Bearer DNS TOCTOU credential sources."""

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


def test_initial_bearer_then_add_header_emits_one_primary_finding(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    req.add_header("Authorization", f"Bearer {api_key}")
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]


def test_initial_bearer_then_direct_header_update_emits_one_primary_finding(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    req.headers["Authorization"] = "Bearer " + api_key
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]


def test_initial_bearer_remove_then_restore_uses_mutation_finding(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    req.remove_header("Authorization")
    req.add_header("Authorization", f"Bearer {api_key}")
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_MUTATION]


def test_unauthenticated_request_then_bearer_mutation_stays_detected(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, data=b"{}")
    req.add_header("Authorization", f"Bearer {api_key}")
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_MUTATION]
