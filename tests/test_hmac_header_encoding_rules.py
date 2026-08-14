"""Source-derived regressions for non-ASCII string HMAC comparison failures."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-auth-header-compare-digest-unicode-string"
_SOURCE_REPOSITORY = "ContextualWisdomLab/newsdom-api"
_VULNERABLE_HEAD_SHA = "04491c0e9ac38b9f793029683cebfb8210ccfadd"
_VULNERABLE_BLOB_SHA = "4efdad56ed78ed5c0158cdf0d746aedfe72604fe"
_FIXED_HEAD_SHA = "e06b1f3fb10903569124af011da213951e6e2473"
_FIXED_BLOB_SHA = "f61aafc2d6592f4a84c7b02b50cfe4a972623463"

_VULNERABLE_SOURCE = '''
from typing import Annotated
import hmac
from fastapi import Header, HTTPException

def require_authorization(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Enforce optional bearer authentication on protected endpoints."""
    token = get_api_token()
    if token is None:
        return
    expected = f"Bearer {token}"
    provided = authorization or ""
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")
'''

_REVIEWED_FIXED_SOURCE = '''
import hmac

def _parse_access_failure(request):
    token = _runtime_settings(request).api_token
    authorization_values = _authorization_values(request)
    if len(authorization_values) != 1:
        return _unauthorized_response()
    provided = authorization_values[0]
    if len(provided) > MAX_BEARER_HEADER_BYTES:
        return _unauthorized_response()
    scheme, separator, credentials = provided.partition(b" ")
    if separator != b" " or scheme.lower() != b"bearer" or not credentials:
        return _unauthorized_response()
    if not hmac.compare_digest(credentials, token.encode("utf-8")):
        return _unauthorized_response()
    return None
'''

_ENCODED_SOURCE = '''
from typing import Annotated
import hmac
from fastapi import Header, HTTPException

def require_authorization(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    token = get_api_token()
    expected = f"Bearer {token}"
    provided = authorization or ""
    if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Unauthorized")
'''

_ASCII_GUARDED_SOURCE = '''
from typing import Annotated
import hmac
from fastapi import Header, HTTPException

def require_authorization(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    token = get_api_token()
    expected = f"Bearer {token}"
    provided = authorization or ""
    if not provided.isascii():
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")
'''

_NON_AUTH_SOURCE = '''
import hmac

def compare_checksums(provided, expected):
    return hmac.compare_digest(provided, expected)
'''


def _rule() -> dict:
    """Return the single packaged rule for the source-derived weakness family."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Run the exact production scanner and isolate this rule's findings."""
    source_file = tmp_path / "main.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_pins_vulnerable_and_fixed_git_objects() -> None:
    """Keep the replay tied to the source repository objects reviewed here."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/newsdom-api"
    assert _VULNERABLE_HEAD_SHA == "04491c0e9ac38b9f793029683cebfb8210ccfadd"
    assert _VULNERABLE_BLOB_SHA == "4efdad56ed78ed5c0158cdf0d746aedfe72604fe"
    assert _FIXED_HEAD_SHA == "e06b1f3fb10903569124af011da213951e6e2473"
    assert _FIXED_BLOB_SHA == "f61aafc2d6592f4a84c7b02b50cfe4a972623463"


def test_packaged_rule_detects_source_derived_unicode_compare_boundary() -> None:
    """Detect the unencoded FastAPI Authorization string comparison."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_packaged_rule_declares_parser_safe_prefilter() -> None:
    """Avoid multiline evaluation outside the source-derived auth contract."""
    assert _rule()["required_substrings"] == (
        "hmac.compare_digest(",
        "Header()",
        "provided = authorization or",
    )


def test_packaged_rule_ignores_reviewed_bytes_boundary() -> None:
    """Keep the current protected Newsdom byte-oriented repair negative."""
    assert not _rule()["pattern"].search(_REVIEWED_FIXED_SOURCE)


def test_packaged_rule_ignores_explicit_utf8_encoding() -> None:
    """Allow both comparison operands to be converted to bytes at the sink."""
    assert not _rule()["pattern"].search(_ENCODED_SOURCE)


def test_packaged_rule_ignores_ascii_guard_before_compare() -> None:
    """Allow a direct ASCII rejection before the string comparator."""
    assert not _rule()["pattern"].search(_ASCII_GUARDED_SOURCE)


def test_packaged_rule_ignores_non_auth_compare_digest() -> None:
    """Do not classify arbitrary digest comparisons as HTTP header failures."""
    assert not _rule()["pattern"].search(_NON_AUTH_SOURCE)


def test_scan_file_emits_normalized_high_finding(tmp_path: Path) -> None:
    """Exercise the detector through production scanning on the vulnerable replay."""
    findings = _scan(_VULNERABLE_SOURCE, tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    expected_line = _VULNERABLE_SOURCE.splitlines().index("def require_authorization(") + 1
    assert finding["line"] == expected_line
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "high"
    assert finding["source"] == "appguardrail-rule"
    assert "CWE-248 - Uncaught Exception" in finding["cwe"]


def test_scan_file_keeps_encoded_and_ascii_guarded_sources_clean(tmp_path: Path) -> None:
    """Preserve both source-derived remediation styles through production scan."""
    assert _scan(_ENCODED_SOURCE, tmp_path) == []
    assert _scan(_ASCII_GUARDED_SOURCE, tmp_path) == []
