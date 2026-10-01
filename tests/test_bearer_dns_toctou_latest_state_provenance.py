"""Current-head provenance regressions for Bearer DNS TOCTOU companions."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_DYNAMIC = "python-bearer-preflight-dns-toctou-dynamic-bearer-replacement"
_UNREDIRECTED = "python-bearer-preflight-dns-toctou-unredirected-header-persistence"
_FAMILY = {
    "python-bearer-preflight-dns-toctou",
    "python-bearer-preflight-dns-toctou-header-mutation",
    "python-bearer-preflight-dns-toctou-multiline-constructor",
    "python-bearer-preflight-dns-toctou-multiline-header-mutation",
    _DYNAMIC,
    _UNREDIRECTED,
}


def _family_findings(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in _FAMILY
    ]


def _dynamic_prefix() -> str:
    return """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
"""


def _unredirected_prefix() -> str:
    return """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
"""


def test_dynamic_uppercase_identifier_assignments_do_not_cancel_lowercase_flow(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    URL = "https://fixed.example"
    endpoint = url.rstrip("/") + "/api/v1/scans"
    ENDPOINT = "https://fixed.example/other"
    req = urllib.request.Request(endpoint)
    replacement = f"bEaReR {api_key}"
    REPLACEMENT = "Basic fixed"
    req.add_header("authorization", replacement)
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_DYNAMIC]


def test_dynamic_replacement_reassignment_before_mutation_breaks_credential_provenance(tmp_path):
    source = _dynamic_prefix() + """\
    replacement = f"Bearer {api_key}"
    replacement = "Basic fixed"
    req.add_header("Authorization", replacement)
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _family_findings(tmp_path, source)


def test_dynamic_request_replacement_before_mutation_breaks_destination_provenance(tmp_path):
    source = _dynamic_prefix() + """\
    replacement = f"Bearer {api_key}"
    req = urllib.request.Request("https://fixed.example/api/v1/scans")
    req.add_header("Authorization", replacement)
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _family_findings(tmp_path, source)


def test_dynamic_self_preserving_reassignments_remain_detectable(tmp_path):
    source = _dynamic_prefix() + """\
    replacement = f"Bearer {api_key}"
    replacement = replacement.strip()
    req = req
    req.add_header("Authorization", replacement)
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_DYNAMIC]


def test_unredirected_validated_url_replacement_before_endpoint_breaks_provenance(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    url = "https://fixed.example"
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers.clear()
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _family_findings(tmp_path, source)


def test_unredirected_endpoint_replacement_before_request_breaks_provenance(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    endpoint = "https://fixed.example/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers.clear()
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _family_findings(tmp_path, source)


def test_unredirected_request_replacement_before_credential_breaks_provenance(tmp_path):
    source = _unredirected_prefix() + """\
    req = urllib.request.Request("https://fixed.example/api/v1/scans")
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers.clear()
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _family_findings(tmp_path, source)


def test_unredirected_fixed_full_url_after_credential_breaks_provenance(tmp_path):
    source = _unredirected_prefix() + """\
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers.clear()
    req.full_url = "https://fixed.example/api/v1/scans"
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _family_findings(tmp_path, source)


def test_unredirected_self_derived_state_remains_detectable(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    endpoint = endpoint + "?retry=1"
    req = urllib.request.Request(endpoint)
    req = req
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers.clear()
    req.full_url = endpoint + "&source=retry"
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_UNREDIRECTED]
