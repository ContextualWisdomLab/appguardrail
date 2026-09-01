"""Regression tests for bearer-authenticated DNS validation TOCTOU detection."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-bearer-preflight-dns-toctou"
_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "security_corpus"


def _rule():
    """Return the packaged DNS validation TOCTOU rule."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _fixture(name: str) -> str:
    """Load one immutable source-backed regression fixture."""
    return (_FIXTURE_DIR / name).read_text(encoding="utf-8")


def _scan_source(tmp_path, source: str):
    """Run the production file scanner and isolate this detector."""
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_rule_declares_high_ssrf_toctou_contract():
    """Keep stable severity and source prefilters for the bounded detector."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["required_substrings"] == (
        "_is_safe_url",
        "urllib.request.Request",
        "Authorization",
        "Bearer",
    )


def test_historical_bearer_preflight_flow_is_detected(tmp_path):
    """Preserve the preflight-check then second-resolution flow as a positive."""
    findings = _scan_source(
        tmp_path,
        _fixture("appguardrail_bearer_dns_toctou_vulnerable.py"),
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert "CWE-367" in finding["cwe"]
    assert "CWE-918" in finding["cwe"]


def test_reviewed_pinned_https_repair_is_not_flagged(tmp_path):
    """The protected transport connects to the validated address set itself."""
    assert not _scan_source(
        tmp_path,
        _fixture("appguardrail_bearer_dns_toctou_fixed.py"),
    )


def test_unauthenticated_urllib_delivery_is_not_flagged(tmp_path):
    """Do not promote generic URL preflight use to this credential-bearing class."""
    source = """\
def deliver(url, payload):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/hook"
    req = urllib.request.Request(endpoint, data=payload)
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_validation_without_network_dispatch_is_not_flagged(tmp_path):
    """A preflight alone has no second-resolution credential exfiltration path."""
    source = """\
def normalize(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return req
"""
    assert not _scan_source(tmp_path, source)


def test_sibling_functions_cannot_donate_dispatch_evidence(tmp_path):
    """Keep the matched preflight, request, and network sink in one function."""
    source = """\
def build(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    return urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )


def dispatch(req):
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)
