"""Regression tests for fail-open empty-host SSRF validator detection."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "tests" / "fixtures" / "security_corpus"
_RULE_ID = "python-ssrf-empty-host-fail-open"


def _rule():
    """Return the single packaged empty-host SSRF validator rule."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _findings(path: Path):
    """Run the production scanner and return only this detector's findings."""
    return [
        finding
        for finding in _scan_file(path, _ROOT)
        if finding["rule_id"] == _RULE_ID
    ]


def _scan_source(tmp_path: Path, source: str):
    """Scan a temporary Python source through the production file scanner."""
    path = tmp_path / "validator.py"
    path.write_text(source, encoding="utf-8")
    return _findings(path)


def test_rule_is_packaged_with_bounded_prefilters():
    """Keep the detector executable and cheap on unrelated Python files."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["required_substrings"] == ("getaddrinfo", "gaierror", "hostname")


def test_historical_appguardrail_vulnerable_fixture_is_detected():
    """Preserve the pre-#1068 AppGuardrail weakness as positive evidence."""
    findings = _findings(_FIXTURES / "appguardrail_empty_host_ssrf_vulnerable.py")

    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "ssrf"
    assert finding["source"] == "appguardrail-rule"
    assert finding["cwe"] == ("CWE-918 - Server-Side Request Forgery",)
    assert finding["line"] > 0


def test_reviewed_fixed_fixture_is_clean():
    """Do not flag the #1068 fail-closed hostname guard."""
    assert not _findings(_FIXTURES / "appguardrail_empty_host_ssrf_fixed.py")


def test_dns_resolution_failure_that_fails_closed_is_clean(tmp_path):
    """A resolver error that explicitly rejects the URL is not the weakness."""
    source = '''
import socket
from urllib.parse import urlparse


def is_safe_url(url):
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return True
'''
    assert not _scan_source(tmp_path, source)


def test_late_empty_host_guard_before_success_is_clean(tmp_path):
    """Avoid a false positive when an equivalent guard appears later in-flow."""
    source = '''
import socket
from urllib.parse import urlparse


def is_safe_url(url):
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    if host == "":
        return False
    return True
'''
    assert not _scan_source(tmp_path, source)


def test_unrelated_dns_probe_is_clean(tmp_path):
    """Do not infer SSRF risk from generic DNS error handling alone."""
    source = '''
import socket


def dns_available(host):
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return True
'''
    assert not _scan_source(tmp_path, source)
