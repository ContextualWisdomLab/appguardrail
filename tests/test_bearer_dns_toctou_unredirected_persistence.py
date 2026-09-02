"""Regression coverage for urllib's separate unredirected header store."""

import re
from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE = "python-bearer-preflight-dns-toctou-unredirected-header-persistence"
_DYNAMIC = "python-bearer-preflight-dns-toctou-dynamic-bearer-replacement"
_FAMILY = {
    "python-bearer-preflight-dns-toctou",
    "python-bearer-preflight-dns-toctou-header-mutation",
    "python-bearer-preflight-dns-toctou-multiline-constructor",
    "python-bearer-preflight-dns-toctou-multiline-header-mutation",
    _DYNAMIC,
    _RULE,
}


def _scan(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return _scan_file(source_file, tmp_path)


def _scan_rule(tmp_path: Path, source: str, rule_id: str = _RULE):
    return [finding for finding in _scan(tmp_path, source) if finding["rule_id"] == rule_id]


def _family_findings(tmp_path: Path, source: str):
    return [finding for finding in _scan(tmp_path, source) if finding["rule_id"] in _FAMILY]


def _prefix() -> str:
    return """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
"""


def test_dynamic_bearer_rule_has_exactly_one_compiled_runtime_entry():
    loaded = [rule for rule in SCAN_RULES if rule["id"] == _DYNAMIC]
    assert len(loaded) == 1
    assert isinstance(loaded[0]["pattern"], re.Pattern)


def test_unredirected_persistence_rule_is_packaged_and_compiled():
    loaded = [rule for rule in SCAN_RULES if rule["id"] == _RULE]
    assert len(loaded) == 1
    assert isinstance(loaded[0]["pattern"], re.Pattern)


def test_headers_clear_does_not_remove_unredirected_bearer(tmp_path):
    source = _prefix() + """\
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers.clear()
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_RULE]


def test_headers_mapping_replacement_does_not_remove_unredirected_bearer(tmp_path):
    source = _prefix() + """\
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers = {}
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_RULE]


def test_headers_pop_does_not_remove_unredirected_bearer(tmp_path):
    source = _prefix() + """\
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers.pop("Authorization", None)
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_RULE]


def test_regular_authorization_overwrite_does_not_remove_unredirected_bearer(tmp_path):
    source = _prefix() + """\
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers["Authorization"] = "Basic dXNlcjpwYXNz"
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_RULE]


def test_multiline_unredirected_bearer_survives_headers_clear(tmp_path):
    source = _prefix() + """\
    req.add_unredirected_header(
        "Authorization",
        f"Bearer {api_key}",
    )
    req.headers.clear()
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_RULE]


def test_remove_header_clears_both_header_stores(tmp_path):
    source = _prefix() + """\
    req.add_unredirected_header("Authorization", f"Bearer {api_key}")
    req.headers.clear()
    req.remove_header("Authorization")
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _family_findings(tmp_path, source)
