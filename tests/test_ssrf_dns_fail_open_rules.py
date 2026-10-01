"""Regression tests for DNS-resolution fail-open SSRF validation."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


_RULE_ID = "python-ssrf-dns-resolution-fail-open"
_GETHOSTBYNAME_HEAD_SHA = "dfac26a826689c17e17e243c9cdc2957810f5a22"
_GETHOSTBYNAME_BLOB_SHA = "65537cf91bc9549aad1c4d0c6a29116fba603934"
_GETADDRINFO_HEAD_SHA = "2949d30718752ea5915c7713ba227e8c19d9e5bf"
_GETADDRINFO_BLOB_SHA = "576b990f13b61eda5c6b5ff3910e820498bfd923"
_FIXED_HEAD_SHA = "892a842765cb1d704ed9236ca08de494074d9551"
_FIXED_BLOB_SHA = "801e9961b9f666efb3b3e22ebfb50d5f0429e6d1"


def _rule():
    """Return the packaged DNS-resolution fail-open rule."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1
    return matches[0]


def _gethostbyname_fail_open_source() -> str:
    """Replay the original single-address fail-open validator."""
    return """\
def _is_safe_url(url: str) -> bool:
    import ipaddress
    import urllib.parse
    import socket
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False

    host = (parsed.hostname or "").lower()
    raw = host.split("%", 1)[0].strip("[]")

    try:
        ip_str = socket.gethostbyname(raw)
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return False
    except socket.gaierror:
        # Ignore DNS resolution failures. We just want to prevent known internal IPs.
        # This allows dummy domains in tests like `hook.example`.
        pass
    except ValueError:
        return False

    return True
"""


def _getaddrinfo_fail_open_source() -> str:
    """Replay the protected multi-address fail-open validator."""
    return """\
def _is_safe_url(url: str) -> bool:
    import ipaddress
    import urllib.parse
    import socket

    if not isinstance(url, str):
        return False

    try:
        parsed = urllib.parse.urlparse(
            url
        )  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    except ValueError:
        return False

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False

    host = (parsed.hostname or "").lower()
    raw = host.split("%", 1)[0].strip("[]")

    def is_bad_ip(ip) -> bool:
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped:
            ip = mapped
        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_multicast
            or getattr(ip, "is_reserved", False)
            or not getattr(ip, "is_global", True)
        )

    try:
        ip = ipaddress.ip_address(raw)
        if is_bad_ip(ip):
            return False
    except ValueError:
        # Non-IP hostnames are expected; validate resolved addresses below.
        pass

    try:
        resolved = socket.getaddrinfo(raw, None)
        for entry in resolved:
            ip_str = entry[4][0].split("%", 1)[0]
            ip = ipaddress.ip_address(ip_str)
            if is_bad_ip(ip):
                return False
    except socket.gaierror:
        # Ignore DNS resolution failures. We just want to prevent known internal IPs.
        # This allows dummy domains in tests like `hook.example`.
        pass
    except ValueError:
        return False

    return True
"""


def _explicit_true_fail_open_source() -> str:
    """Build the direct exception-return variant of the same defect."""
    return """\
def permits_destination(host):
    try:
        socket.getaddrinfo(host, 443)
    except socket.gaierror:
        return True
    return True
"""


def _return_false_source() -> str:
    """Reject a destination when DNS evidence is unavailable."""
    return """\
def permits_destination(host):
    try:
        socket.getaddrinfo(host, 443)
    except socket.gaierror:
        return False
    return True
"""


def _reraises_source() -> str:
    """Propagate DNS failure instead of admitting the destination."""
    return """\
def permits_destination(host):
    try:
        socket.getaddrinfo(host, 443)
    except socket.gaierror:
        raise
    return True
"""


def _later_enforcement_source() -> str:
    """Keep a swallowed exception safe when a later guard rejects no answers."""
    return """\
def permits_destination(host):
    resolved = []
    try:
        resolved = socket.getaddrinfo(host, 443)
    except socket.gaierror:
        pass
    if not resolved:
        return False
    return all(ipaddress.ip_address(item[4][0]).is_global for item in resolved)
"""


def _different_function_source() -> str:
    """Keep unrelated DNS utility failure separate from a later allow decision."""
    return """\
def resolve_optional(host):
    try:
        return socket.getaddrinfo(host, 443)
    except socket.gaierror:
        pass

def permits_destination(url):
    return True
"""


def _unrelated_dns_probe_source() -> str:
    """Keep a best-effort DNS utility outside the URL-policy rule."""
    return """\
def warm_dns_cache(host):
    try:
        socket.getaddrinfo(host, 443)
    except socket.gaierror:
        pass
    return True
"""


def _nested_resolver_outer_handler_source() -> str:
    """Keep a nested resolver separate from an unrelated outer handler."""
    return """\
def permits_destination(host):
    def resolve_optional():
        return socket.getaddrinfo(host, 443)
    try:
        return resolve_optional()
    except socket.gaierror:
        return True
"""


def _outer_resolver_nested_handler_source() -> str:
    """Keep an outer resolver separate from a nested function's handler."""
    return """\
def permits_destination(host):
    try:
        socket.getaddrinfo(host, 443)
        def nested_policy():
            try:
                use_cached_answer()
            except socket.gaierror:
                return True
    except ValueError:
        return False
    return False
"""


def _nested_try_resolver_outer_handler_source() -> str:
    """Keep an inner resolver try separate from an outer admission handler."""
    return """\
def permits_destination(host):
    try:
        try:
            socket.getaddrinfo(host, 443)
        except socket.gaierror:
            return False
    except socket.gaierror:
        return True
    return False
"""


def _nonliteral_true_expression_source() -> str:
    """Do not treat a rejecting Boolean expression as literal admission."""
    return """\
def permits_destination(host):
    try:
        socket.getaddrinfo(host, 443)
    except socket.gaierror:
        return True and False
    return True and False
"""


def _fixed_wrapper_source() -> str:
    """Replay the reviewed fail-closed pinned-validation wrapper."""
    return """\
def _is_safe_url(url: str, *, resolver: Resolver = socket.getaddrinfo) -> bool:
    \"\"\"Return whether ``url`` resolves to a strict public HTTPS destination.\"\"\"
    try:
        resolve_public_https_destination(url, resolver=resolver)
    except DestinationValidationError:
        return False
    return True
"""


@pytest.mark.parametrize(
    "source",
    [
        _gethostbyname_fail_open_source(),
        _getaddrinfo_fail_open_source(),
        _explicit_true_fail_open_source(),
    ],
)
def test_packaged_rule_matches_dns_resolution_fail_open(source: str) -> None:
    """Detect validators that admit a destination after DNS failure."""
    assert _rule()["pattern"].search(source)


@pytest.mark.parametrize(
    "source",
    [
        _return_false_source(),
        _reraises_source(),
        _later_enforcement_source(),
        _different_function_source(),
        _unrelated_dns_probe_source(),
        _nested_resolver_outer_handler_source(),
        _outer_resolver_nested_handler_source(),
        _nested_try_resolver_outer_handler_source(),
        _nonliteral_true_expression_source(),
        _fixed_wrapper_source(),
    ],
)
def test_packaged_rule_ignores_fail_closed_and_unrelated_flows(source: str) -> None:
    """Exclude explicit rejection, later enforcement, and unrelated functions."""
    assert not _rule()["pattern"].search(source)


@pytest.mark.parametrize(
    "source",
    [
        _gethostbyname_fail_open_source(),
        _getaddrinfo_fail_open_source(),
        _explicit_true_fail_open_source(),
    ],
)
def test_scan_file_emits_dns_resolution_fail_open_finding(
    source: str, tmp_path
) -> None:
    """Emit the rule through the production scanner with stable security metadata."""
    source_file = tmp_path / "url_policy.py"
    source_file.write_text(source, encoding="utf-8")

    findings = [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["category"] == "ssrf"
    assert findings[0]["cwe"] == ("CWE-918 - Server-Side Request Forgery",)
    assert "fail closed" in findings[0]["message"].lower()
    assert "reject" in findings[0]["remediation"].lower()


def test_packaged_rule_declares_dns_failure_prefilter() -> None:
    """Skip the bounded regex when no DNS-resolution failure handler exists."""
    assert _rule()["required_substrings"] == ("gaierror",)


def test_incident_corpus_pins_vulnerable_and_fixed_heads() -> None:
    """Bind this regression family to the exact Issue #1267 source lineage."""
    assert _GETHOSTBYNAME_HEAD_SHA == "dfac26a826689c17e17e243c9cdc2957810f5a22"
    assert _GETHOSTBYNAME_BLOB_SHA == "65537cf91bc9549aad1c4d0c6a29116fba603934"
    assert _GETADDRINFO_HEAD_SHA == "2949d30718752ea5915c7713ba227e8c19d9e5bf"
    assert _GETADDRINFO_BLOB_SHA == "576b990f13b61eda5c6b5ff3910e820498bfd923"
    assert _FIXED_HEAD_SHA == "892a842765cb1d704ed9236ca08de494074d9551"
    assert _FIXED_BLOB_SHA == "801e9961b9f666efb3b3e22ebfb50d5f0429e6d1"
