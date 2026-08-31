"""Source-authoritative regressions for fail-open authentication secrets."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-auth-secret-missing-fail-open"
_RULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scanner"
    / "rules"
    / "fail_open_auth_secret.yml"
)
_SOURCE_REPOSITORY = "ContextualWisdomLab/newsdom-api"
_SOURCE_PR = 539
_VULNERABLE_HEAD_SHA = "04491c0e9ac38b9f793029683cebfb8210ccfadd"
_VULNERABLE_BLOB_SHA = "4efdad56ed78ed5c0158cdf0d746aedfe72604fe"
_REVIEWED_FIX_HEAD_SHA = "e22bb76bcf821dfa21deb83938a474c6cf3e7c1e8"
_PROTECTED_MERGE_SHA = "76417bd240398c1a4bf2f6c65d693ea523b179d0"
_REVIEWED_FIX_BLOB_SHA = "f61aafc2d6592f4a84c7b02b50cfe4a972623463"

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
    settings = _runtime_settings(request)
    if settings.authentication_mode is AuthenticationMode.DISABLED:
        return None
    token = settings.api_token
    if token is None:
        return JSONResponse(
            status_code=503,
            content={"detail": SERVICE_UNAVAILABLE_DETAIL},
        )
    authorization_values = _authorization_values(request)
    if len(authorization_values) != 1:
        return _unauthorized_response()
    provided = authorization_values[0]
    scheme, separator, credentials = provided.partition(b" ")
    if separator != b" " or scheme.lower() != b"bearer" or not credentials:
        return _unauthorized_response()
    if not hmac.compare_digest(credentials, token.encode("utf-8")):
        return _unauthorized_response()
    return None
'''

_FAIL_CLOSED_EXCEPTION_SOURCE = '''
def require_authorization(authorization: str | None = None) -> None:
    token = get_api_token()
    if token is None:
        raise HTTPException(status_code=503, detail="Service Unavailable")
    expected = f"Bearer {token}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
'''

_FAIL_CLOSED_RESPONSE_SOURCE = '''
def check_authentication(request: Request) -> JSONResponse | None:
    token = settings.api_token
    if token is None:
        return JSONResponse(status_code=503, content={"detail": "Unavailable"})
    expected = f"Bearer {token}"
    if request.headers.get("authorization") != expected:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return None
'''

_EXPLICIT_DEVELOPMENT_BYPASS_SOURCE = '''
def require_authorization(request: Request) -> JSONResponse | None:
    if settings.authentication_mode is AuthenticationMode.DISABLED:
        return None
    token = settings.api_token
    if token is None:
        return JSONResponse(status_code=503, content={"detail": "Unavailable"})
    expected = f"Bearer {token}"
    if request.headers.get("authorization") != expected:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return None
'''

_UNRELATED_OPTIONAL_CONFIG_SOURCE = '''
def configure_telemetry() -> None:
    token = get_api_token()
    if token is None:
        return
    telemetry.configure(token=token)
'''

_ADJACENT_FUNCTION_SOURCE = '''
def load_optional_token() -> None:
    token = get_api_token()
    if token is None:
        return


def require_authorization(authorization: str | None = None) -> None:
    token = get_api_token()
    expected = f"Bearer {token}"
    if authorization != expected:
        raise HTTPException(status_code=401)
'''

_COMMENT_ONLY_BEARER_SOURCE = '''
def require_authorization(authorization: str | None = None) -> None:
    token = get_api_token()
    if token is None:
        return
    # Bearer authentication is performed by an upstream proxy.
    audit_request()
'''

_LOG_ONLY_BEARER_SOURCE = '''
def verify_authentication(authorization: str | None = None) -> None:
    token = get_api_token()
    if token is None:
        return
    logger.info("Bearer authentication is configured elsewhere")
'''

_LATER_CLASS_BEARER_SOURCE = '''
def check_authentication(authorization: str | None = None) -> None:
    token = get_api_token()
    if token is None:
        return
    audit_request()


class BearerPolicy:
    pass
'''

_NESTED_CLASS_VULNERABLE_SOURCE = '''
def require_authorization(authorization: str | None = None) -> None:
    class AuditContext:
        pass

    token = get_api_token()
    if token is None:
        return
    expected = f"Bearer {token}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
'''


def _rule() -> dict:
    """Return the packaged missing-auth-secret fail-open rule."""
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
    """Preserve exact vulnerable, reviewed-fix, merge, and blob identities."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/newsdom-api"
    assert _SOURCE_PR == 539
    assert _VULNERABLE_HEAD_SHA == "04491c0e9ac38b9f793029683cebfb8210ccfadd"
    assert _VULNERABLE_BLOB_SHA == "4efdad56ed78ed5c0158cdf0d746aedfe72604fe"
    assert _REVIEWED_FIX_HEAD_SHA == "e22bb76bcf821dfa21deb83938a474c6cf3e7c1e8"
    assert _PROTECTED_MERGE_SHA == "76417bd240398c1a4bf2f6c65d693ea523b179d0"
    assert _REVIEWED_FIX_BLOB_SHA == "f61aafc2d6592f4a84c7b02b50cfe4a972623463"


def test_rule_file_declares_non_executable_detection_data_boundary() -> None:
    """Keep detector signatures clearly separated from runtime application code."""
    source = _RULE_PATH.read_text(encoding="utf-8")
    assert "# AppGuardrail detector artifact: non-executable SAST signature data." in source
    assert (
        "# Vulnerable source shapes below describe detection targets, not AppGuardrail runtime code."
        in source
    )


def test_rule_file_has_one_taxonomy_source_of_truth() -> None:
    """Keep public taxonomy references in message metadata parsed by the loader."""
    source = _RULE_PATH.read_text(encoding="utf-8")
    assert "\n    cwe:" not in source
    assert "\n    owasp:" not in source


def test_rule_detects_missing_secret_that_returns_from_authentication() -> None:
    """Detect the source-authoritative missing-secret authentication bypass."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_rule_prefilters_bound_authentication_and_secret_evidence() -> None:
    """Avoid multiline matching without the observed auth and secret signals."""
    assert _rule()["required_substrings"] == (
        "token is None",
        "Bearer",
    )


def test_rule_ignores_protected_fail_closed_response() -> None:
    """Keep the protected 503-on-missing-secret repair clean."""
    assert not _rule()["pattern"].search(_REVIEWED_FIXED_SOURCE)


def test_rule_ignores_fail_closed_exception() -> None:
    """Do not flag authentication code that rejects absent server secrets."""
    assert not _rule()["pattern"].search(_FAIL_CLOSED_EXCEPTION_SOURCE)


def test_rule_ignores_fail_closed_response_object() -> None:
    """Do not confuse an explicit denial response with a bare allow-through return."""
    assert not _rule()["pattern"].search(_FAIL_CLOSED_RESPONSE_SOURCE)


def test_rule_ignores_explicit_development_mode_with_fail_closed_secret() -> None:
    """Allow an explicit development opt-out when missing required secrets still deny."""
    assert not _rule()["pattern"].search(_EXPLICIT_DEVELOPMENT_BYPASS_SOURCE)


def test_rule_ignores_unrelated_optional_configuration() -> None:
    """Require authentication/Bearer context rather than any optional token getter."""
    assert not _rule()["pattern"].search(_UNRELATED_OPTIONAL_CONFIG_SOURCE)


def test_rule_does_not_cross_adjacent_function_boundary() -> None:
    """Do not pair an optional token return with another function's auth sink."""
    assert not _rule()["pattern"].search(_ADJACENT_FUNCTION_SOURCE)


def test_rule_ignores_bearer_text_in_comment() -> None:
    """Do not turn explanatory Bearer comments into deploy-blocking evidence."""
    assert not _rule()["pattern"].search(_COMMENT_ONLY_BEARER_SOURCE)


def test_rule_ignores_bearer_text_in_log_message() -> None:
    """Require authentication logic rather than a string-only logging mention."""
    assert not _rule()["pattern"].search(_LOG_ONLY_BEARER_SOURCE)


def test_rule_does_not_cross_class_boundary_for_bearer_signal() -> None:
    """Do not borrow a Bearer class name from code after the guarded function."""
    assert not _rule()["pattern"].search(_LATER_CLASS_BEARER_SOURCE)


def test_rule_detects_guard_with_nested_class_before_bearer_check() -> None:
    """Keep nested class declarations inside the enclosing authentication function."""
    assert _rule()["pattern"].search(_NESTED_CLASS_VULNERABLE_SOURCE)


def test_scan_file_emits_normalized_missing_authentication_finding(tmp_path: Path) -> None:
    """Exercise the production scanner and normalized authentication metadata."""
    findings = _scan(_VULNERABLE_SOURCE, tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["confidence"] == "high"
    assert finding["category"] == "authz"
    assert finding["remediation"] == (
        "Configure the required server-side authentication credential and fail closed "
        "when it is unavailable; never treat a missing credential as authentication "
        "being disabled."
    )
    assert finding["cwe"] == (
        "CWE-306 - Missing Authentication for Critical Function",
    )
    assert finding["owasp"] == (
        "OWASP A07:2025 - Authentication Failures",
    )


def test_scan_file_keeps_protected_fix_clean(tmp_path: Path) -> None:
    """Verify the source-authoritative fixed negative through production scanning."""
    assert _scan(_REVIEWED_FIXED_SOURCE, tmp_path) == []
