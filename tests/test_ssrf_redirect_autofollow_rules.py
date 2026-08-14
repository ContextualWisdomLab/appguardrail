"""Source-authoritative RED tests for SSRF redirect-autofollow bypasses."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-ssrf-redirect-autofollow-after-validation"
_SOURCE_REPOSITORY = "ContextualWisdomLab/appguardrail"
_VULNERABLE_HEAD_SHA = "5a7cb7e7237532ffb4366b4d4dc758d0df8993fc"
_VULNERABLE_BLOB_SHA = "07300b0f0df3b7c61c9304812836a4b541a67e6b"
_FIXED_HEAD_SHA = "814e8bf982c27d5aba10ba7ab28b2540ce601c3e"
_FIXED_BLOB_SHA = "bf74784ecd168685153700150020648e4ee4e806"

_VULNERABLE_SOURCE = """
def _is_safe_url(url: str) -> bool:
    return url.startswith(("http://", "https://"))


def _send_alert(url: str, payload: dict) -> bool:
    import urllib.request
    if not _is_safe_url(url):
        return False
    req = urllib.request.Request(url, data=b"{}", method="POST")
    urllib.request.urlopen(req, timeout=10)
    return True
"""

_FIXED_SOURCE = """
import urllib.error
import urllib.request


def _is_safe_url(url: str) -> bool:
    return url.startswith(("http://", "https://"))


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_safe_url(newurl):
            raise urllib.error.URLError("Unsafe redirect target")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _send_alert(url: str, payload: dict) -> bool:
    if not _is_safe_url(url):
        return False
    req = urllib.request.Request(url, data=b"{}", method="POST")
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(req, timeout=10)
    return True
"""

_NO_PREVALIDATION_SOURCE = """
import urllib.request


def fetch(url: str):
    return urllib.request.urlopen(url, timeout=10)
"""

_NON_NETWORK_URLLIB_SOURCE = """
from pathlib import Path


def read_file(path: str):
    if not _is_safe_url(path):
        return None
    return Path(path).read_text(encoding="utf-8")
"""


def _rule():
    """Return the single packaged redirect-autofollow rule under test."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Execute the production scanner and isolate redirect-bypass findings."""
    source_file = tmp_path / "delivery.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_is_explicit_and_immutable() -> None:
    """Pin the vulnerable and reviewed-fix AppGuardrail source identities."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/appguardrail"
    assert _VULNERABLE_HEAD_SHA == "5a7cb7e7237532ffb4366b4d4dc758d0df8993fc"
    assert _VULNERABLE_BLOB_SHA == "07300b0f0df3b7c61c9304812836a4b541a67e6b"
    assert _FIXED_HEAD_SHA == "814e8bf982c27d5aba10ba7ab28b2540ce601c3e"
    assert _FIXED_BLOB_SHA == "bf74784ecd168685153700150020648e4ee4e806"


def test_packaged_rule_detects_validated_urlopen_autofollow() -> None:
    """Detect initial URL validation followed by redirect-following urlopen."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_packaged_rule_declares_bounded_prefilter() -> None:
    """Avoid multiline evaluation outside the exact urllib SSRF contract."""
    assert _rule()["required_substrings"] == (
        "_is_safe_url",
        "urllib.request",
        "urlopen",
    )


def test_packaged_rule_ignores_redirect_revalidation_handler() -> None:
    """Do not flag the reviewed fix that revalidates every redirect target."""
    assert not _rule()["pattern"].search(_FIXED_SOURCE)


def test_packaged_rule_does_not_claim_generic_unvalidated_urlopen() -> None:
    """Keep generic SSRF outside this source-derived redirect-bypass slice."""
    assert not _rule()["pattern"].search(_NO_PREVALIDATION_SOURCE)


def test_packaged_rule_ignores_non_network_url_validation() -> None:
    """Require urllib network dispatch rather than any URL-named validation."""
    assert not _rule()["pattern"].search(_NON_NETWORK_URLLIB_SOURCE)


def test_scan_file_emits_normalized_high_finding(tmp_path: Path) -> None:
    """Verify the exact production finding envelope for the source replay."""
    findings = _scan(_VULNERABLE_SOURCE, tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "ssrf"
    assert finding["confidence"] == "high"
    assert finding["source"] == "appguardrail-rule"
    assert finding["cwe"] == ("CWE-918 - Server-Side Request Forgery",)
    assert finding["owasp"] == ("OWASP A10:2021 - Server-Side Request Forgery",)


def test_scan_file_does_not_flag_reviewed_fix(tmp_path: Path) -> None:
    """Keep the redirect-revalidating reviewed source clean in production scan."""
    assert _scan(_FIXED_SOURCE, tmp_path) == []
