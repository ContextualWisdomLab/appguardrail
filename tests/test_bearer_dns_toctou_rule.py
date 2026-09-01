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


def test_one_line_bearer_request_is_detected(tmp_path):
    """Formatting the Request on one line must not hide the DNS race."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {api_key}"})
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_one_line_bearer_request_with_trailing_comment_is_detected(tmp_path):
    """A trailing Request comment cannot erase executable bearer evidence."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {api_key}"})  # authenticated push
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_concatenated_bearer_header_is_detected(tmp_path):
    """String concatenation is the same credential-bearing request semantics."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": "Bearer " + api_key},
    )  # request is still executable
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_comment_before_fail_closed_guard_return_is_detected(tmp_path):
    """A harmless guard comment must not make the vulnerable delivery invisible."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        # Reject destinations that fail the public URL preflight.
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_with_urlopen_bearer_dispatch_is_detected(tmp_path):
    """Context-manager urlopen still performs the second DNS-sensitive dispatch."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.read()
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_isolated_pinned_opener_repair_is_not_flagged(tmp_path):
    """Changing only the connection primitive to a pinned opener is sufficient."""
    assert not _scan_source(
        tmp_path,
        _fixture("appguardrail_bearer_dns_toctou_fixed.py"),
    )


def test_protected_pinned_https_repair_is_not_flagged(tmp_path):
    """Keep the actual protected PR #898 transport repair as a negative oracle."""
    assert not _scan_source(
        tmp_path,
        _fixture("appguardrail_bearer_dns_toctou_protected.py"),
    )


def test_custom_pinned_opener_is_not_assumed_to_reresolve(tmp_path):
    """An arbitrary opener is not evidence that the network layer repeats DNS."""
    source = """\
def deliver(url, payload, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
        },
    )
    opener = DNSPinnedOpener(validated_url=url)
    return opener.open(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_commented_request_and_dispatch_are_not_executable_evidence(tmp_path):
    """Comments cannot donate a bearer request or second-resolution sink."""
    source = """\
def deliver(url, payload, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    # req = urllib.request.Request(
    #     endpoint,
    #     headers={"Authorization": f"Bearer {api_key}"},
    # )
    # return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert not _scan_source(tmp_path, source)


def test_commented_bearer_header_cannot_authenticate_live_request(tmp_path):
    """A comment inside a live Request call cannot donate bearer credentials."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        # headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_commented_concatenated_bearer_header_is_not_evidence(tmp_path):
    """The new concatenation form still cannot be sourced from a comment."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        # headers={"Authorization": "Bearer " + api_key},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_mutually_exclusive_request_and_dispatch_are_not_one_path(tmp_path):
    """Evidence from opposite branches cannot form one executable vulnerable path."""
    source = """\
def deliver(url, payload, api_key, construct):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    if construct:
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
            },
        )
    else:
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert not _scan_source(tmp_path, source)


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


def test_assigned_urlopen_dispatch_is_detected(tmp_path):
    """Assignment form does not remove the second-resolution network sink."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    response = urllib.request.urlopen(
        req,
        timeout=5,
    )
    return response
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_assigned_reviewed_opener_dispatch_is_detected(tmp_path):
    """Assignment through the reviewed urllib opener remains a vulnerable sink."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    opener = urllib.request.build_opener(SafeRedirectHandler())
    response = opener.open(
        req,
        timeout=5,
    )
    return response
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_dead_sink_after_unconditional_return_is_not_flagged(tmp_path):
    """Unreachable dispatch cannot complete the credential exfiltration path."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return None
    response = urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_unrelated_request_replacement_is_not_flagged(tmp_path):
    """Replacing the tracked request breaks the vulnerable request provenance."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    req = object()
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_unrelated_endpoint_replacement_is_not_flagged(tmp_path):
    """Replacing the URL-derived endpoint before Request breaks destination flow."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/")
    endpoint = "https://fixed.example/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_endpoint_self_derivation_remains_detected(tmp_path):
    """A reassignment derived from the tracked endpoint preserves unsafe provenance."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/")
    endpoint = endpoint + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_request_preserving_reassignment_remains_detected(tmp_path):
    """A direct self-assignment cannot sanitize the tracked bearer request."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    req = req
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_endpoint_name_only_inside_replacement_string_is_not_flagged(tmp_path):
    """Quoted identifier text is not executable provenance for endpoint flow."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/")
    endpoint = choose("endpoint")
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_request_name_only_inside_replacement_string_is_not_flagged(tmp_path):
    """Quoted identifier text is not executable provenance for request flow."""
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    req = choose("req")
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)
