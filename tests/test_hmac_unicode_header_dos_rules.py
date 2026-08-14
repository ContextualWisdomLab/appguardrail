"""Source-authoritative regressions for Unicode bearer HMAC comparison failures."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-hmac-compare-digest-unicode-header-dos"
_SOURCE_REPOSITORY = "ContextualWisdomLab/newsdom-api"
_SOURCE_PR = 539
_VULNERABLE_HEAD_SHA = "04491c0e9ac38b9f793029683cebfb8210ccfadd"
_VULNERABLE_BLOB_SHA = "4efdad56ed78ed5c0158cdf0d746aedfe72604fe"
_REVIEWED_FIX_HEAD_SHA = "e22bb76bcf821dfa21eb83938a474c6cf3e7c1e8"
_REVIEWED_FIX_BLOB_SHA = "f61aafc2d6592f4a84c7b02b50cfe4a972623463"
_PROTECTED_MERGE_SHA = "76417bd240398c1a4bf2f6c65d693ea523b179d0"

_VULNERABLE_SOURCE = '''
def require_authorization(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    token = get_api_token()
    if token is None:
        return
    expected = f"Bearer {token}"
    provided = authorization or ""
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")
'''

_REVIEWED_FIXED_SOURCE = '''
def _parse_access_failure(request: Request) -> JSONResponse | None:
    token = settings.api_token
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

_ENCODED_STRING_SOURCE = '''
def require_authorization(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    expected = f"Bearer {get_api_token()}"
    provided = authorization or ""
    if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401)
'''

_HEXDIGEST_SOURCE = '''
def verify_signature(provided: str, expected: str) -> bool:
    return hmac.compare_digest(provided, expected)
'''

_NON_HMAC_HEADER_SOURCE = '''
def require_authorization(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    if authorization != "Bearer expected":
        raise HTTPException(status_code=401)
'''

_ADJACENT_ASYNC_FUNCTION_SOURCE = '''
def read_authorization(
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    provided = authorization or ""
    return provided

async def compare_unrelated_value() -> bool:
    expected = "constant"
    provided = "constant"
    return hmac.compare_digest(provided, expected)
'''


def _rule() -> dict:
    """Return the packaged Unicode-header HMAC rule."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Run the production scanner over one Python source replay."""
    source_file = tmp_path / "main.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_pins_vulnerable_and_protected_fix() -> None:
    """Preserve exact source, vulnerable blob, reviewed fix, and merge identity."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/newsdom-api"
    assert _SOURCE_PR == 539
    assert _VULNERABLE_HEAD_SHA == "04491c0e9ac38b9f793029683cebfb8210ccfadd"
    assert _VULNERABLE_BLOB_SHA == "4efdad56ed78ed5c0158cdf0d746aedfe72604fe"
    assert _REVIEWED_FIX_HEAD_SHA == "e22bb76bcf821dfa21eb83938a474c6cf3e7c1e8"
    assert _REVIEWED_FIX_BLOB_SHA == "f61aafc2d6592f4a84c7b02b50cfe4a972623463"
    assert _PROTECTED_MERGE_SHA == "76417bd240398c1a4bf2f6c65d693ea523b179d0"


def test_rule_detects_raw_header_strings_passed_to_compare_digest() -> None:
    """Detect raw FastAPI header strings passed to ASCII-only compare_digest."""
    rule = _rule()
    assert rule["severity"] == "MEDIUM"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_rule_declares_bounded_source_and_sink_prefilters() -> None:
    """Avoid multiline regex work outside the observed authorization boundary."""
    assert _rule()["required_substrings"] == (
        "Header()",
        "hmac.compare_digest",
        "authorization",
    )


def test_rule_ignores_reviewed_byte_level_fix() -> None:
    """Keep the protected byte-oriented authentication boundary clean."""
    assert not _rule()["pattern"].search(_REVIEWED_FIXED_SOURCE)


def test_rule_ignores_explicit_utf8_encoding_before_compare() -> None:
    """Do not flag string sources converted to bytes before comparison."""
    assert not _rule()["pattern"].search(_ENCODED_STRING_SOURCE)


def test_rule_ignores_generic_ascii_hexdigest_comparison() -> None:
    """Require the HTTP Header source rather than generic compare_digest use."""
    assert not _rule()["pattern"].search(_HEXDIGEST_SOURCE)


def test_rule_ignores_header_checks_without_compare_digest() -> None:
    """Require the documented Python HMAC sink contract."""
    assert not _rule()["pattern"].search(_NON_HMAC_HEADER_SOURCE)


def test_rule_does_not_cross_adjacent_async_function_boundary() -> None:
    """Do not pair a header source with an unrelated async function HMAC sink."""
    assert not _rule()["pattern"].search(_ADJACENT_ASYNC_FUNCTION_SOURCE)


def test_scan_file_emits_normalized_uncaught_exception_finding(tmp_path: Path) -> None:
    """Exercise the production scanner and normalized CWE evidence."""
    findings = _scan(_VULNERABLE_SOURCE, tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "MEDIUM"
    assert finding["source"] == "appguardrail-rule"
    assert finding["confidence"] == "high"
    assert finding["cwe"] == (
        "CWE-248 - Uncaught Exception",
    )


def test_scan_file_keeps_reviewed_fix_clean(tmp_path: Path) -> None:
    """Verify the source-authoritative fixed negative via production scanning."""
    assert _scan(_REVIEWED_FIXED_SOURCE, tmp_path) == []
