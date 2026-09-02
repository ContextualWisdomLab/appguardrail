"""Regression boundaries for post-construction urllib Request state mutations."""

import re
from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_PRIMARY = "python-bearer-preflight-dns-toctou"
_DYNAMIC = "python-bearer-preflight-dns-toctou-dynamic-bearer-replacement"
_FAMILY = {
    _PRIMARY,
    "python-bearer-preflight-dns-toctou-header-mutation",
    "python-bearer-preflight-dns-toctou-multiline-constructor",
    "python-bearer-preflight-dns-toctou-multiline-header-mutation",
    _DYNAMIC,
}


def _scan_source(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in _FAMILY
    ]


def _direct_bearer_prefix() -> str:
    return """\
def deliver(url, api_key, replacement=None):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
"""


def test_dynamic_bearer_companion_is_packaged_once_and_compiled():
    loaded = [rule for rule in SCAN_RULES if rule["id"] == _DYNAMIC]
    assert len(loaded) == 1
    assert isinstance(loaded[0]["pattern"], re.Pattern)


def test_dynamic_authorization_assignment_breaks_unproven_bearer_state(tmp_path):
    source = _direct_bearer_prefix() + """\
    req.headers["Authorization"] = replacement
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_dynamic_add_header_breaks_unproven_bearer_state(tmp_path):
    source = _direct_bearer_prefix() + """\
    req.add_header("Authorization", replacement)
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_headers_mapping_replacement_breaks_bearer_state(tmp_path):
    source = _direct_bearer_prefix() + """\
    req.headers = {}
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_headers_clear_breaks_bearer_state(tmp_path):
    source = _direct_bearer_prefix() + """\
    req.headers.clear()
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_fixed_full_url_replacement_breaks_destination_provenance(tmp_path):
    source = _direct_bearer_prefix() + """\
    req.full_url = "https://fixed.example/api/v1/scans"
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_self_derived_full_url_mutation_preserves_destination_provenance(tmp_path):
    source = _direct_bearer_prefix() + """\
    req.full_url = endpoint + "?source=retry"
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _scan_source(tmp_path, source)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == _PRIMARY


def test_provable_dynamic_bearer_assignment_remains_detectable(tmp_path):
    source = _direct_bearer_prefix() + """\
    replacement = f"Bearer {api_key}"
    req.headers["Authorization"] = replacement
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _scan_source(tmp_path, source)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == _DYNAMIC


def test_provable_dynamic_bearer_add_header_remains_detectable(tmp_path):
    source = _direct_bearer_prefix() + """\
    replacement = "Bearer " + api_key
    req.add_header("Authorization", replacement)
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _scan_source(tmp_path, source)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == _DYNAMIC


def test_dynamic_bearer_then_header_clear_is_sanitized(tmp_path):
    source = _direct_bearer_prefix() + """\
    replacement = f"Bearer {api_key}"
    req.headers["Authorization"] = replacement
    req.headers.clear()
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_dynamic_bearer_then_opaque_replacement_is_sanitized(tmp_path):
    source = _direct_bearer_prefix() + """\
    replacement = f"Bearer {api_key}"
    req.headers["Authorization"] = replacement
    req.headers["Authorization"] = fallback
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_dynamic_bearer_then_fixed_destination_is_sanitized(tmp_path):
    source = _direct_bearer_prefix() + """\
    replacement = f"Bearer {api_key}"
    req.headers["Authorization"] = replacement
    req.full_url = "https://fixed.example/api/v1/scans"
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)
