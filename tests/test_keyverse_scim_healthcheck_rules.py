"""Source-derived regressions for Keyverse SCIM tombstones and health URL schemes."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_SCIM_RULE_ID = "python-scim-put-tombstone-resurrection"
_HEALTH_RULE_ID = "python-healthcheck-unrestricted-url-scheme"
_SOURCE_REPOSITORY = "ContextualWisdomLab/keyverse"
_VULNERABLE_HEAD_SHA = "938530663fc9c4129fd309f81f8f44b147728b1e"
_FIXED_HEAD_SHA = "ce207dfd42975db61c82a5963e206fc1db14ac2b"
_VULNERABLE_SCIM_BLOB_SHA = "2cb7609c1bd934670cba1a513f64908f8225601f"
_FIXED_SCIM_BLOB_SHA = "4c0b9fbca9d54a9c2237baf3879512ba17a4295d"
_VULNERABLE_HEALTH_BLOB_SHA = "4284510ce94ac7148aeaec860b69b65d538b4acb"
_FIXED_HEALTH_BLOB_SHA = "fd33ac621a2c7c86553ee3049e98d7ac91189186"

_VULNERABLE_SCIM_SOURCE = '''
@scim_router.put("/Users/{user_id}")
def replace_user(
    user_id: str,
    resource: dict[str, Any],
    provisioner: AdminApi = Depends(get_provisioner),
) -> Response:
    """Replace a provisioned user from a SCIM PUT request."""
    try:
        provisioner.get_user(user_id)
    except KeyError as exc:
        raise _scim_error(404, f"user '{user_id}' not found") from exc
    account = _to_user_account(resource, user_id=user_id)
    provisioner.replace_user(user_id, account)
    return _scim_response(_to_scim_resource(provisioner.get_user(user_id)))
'''

_FIXED_SCIM_SOURCE = '''
@scim_router.put("/Users/{user_id}")
def replace_user(
    user_id: str,
    resource: dict[str, Any],
    provisioner: AdminApi = Depends(get_provisioner),
    user_operation_locks: UserOperationLocks = Depends(get_user_operation_locks),
) -> Response:
    """Replace a provisioned user from a SCIM PUT request."""
    try:
        with user_operation_locks.hold(user_id):
            try:
                provisioner.get_user(user_id)
            except KeyError as exc:
                raise _scim_error(404, f"user '{user_id}' not found") from exc
            if provisioner.get_user_attribute(user_id, TOMBSTONE_ATTRIBUTE_KEY):
                raise _scim_error(409, f"user '{user_id}' has been merged")
            account = _to_user_account(resource, user_id=user_id)
            provisioner.replace_user(user_id, account)
            replaced = provisioner.get_user(user_id)
    except UserOperationLockTimeout as exc:
        raise _scim_error(503, f"user '{user_id}' is being modified") from exc
    return _scim_response(_to_scim_resource(replaced))
'''

_ALTERNATE_SCIM_GUARD_SOURCE = '''
@scim_router.put("/Users/{user_id}")
def replace_user(user_id, resource, provisioner=Depends(get_provisioner)):
    existing = provisioner.get_user(user_id)
    if existing.merged_into_user_id:
        raise _scim_error(409, "merged account is immutable")
    account = _to_user_account(resource, user_id=user_id)
    provisioner.replace_user(user_id, account)
    return _scim_response(_to_scim_resource(provisioner.get_user(user_id)))
'''

_VULNERABLE_HEALTH_SOURCE = '''
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8099/healthz"

def main(url: str = DEFAULT_URL) -> int:
    """Check the configured health endpoint and return a shell status code."""
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = response.read()
    except Exception:
        return 1
    return 0 if body else 1
'''

_FIXED_HEALTH_SOURCE = '''
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8099/healthz"
_ALLOWED_SCHEMES = frozenset({"http", "https"})

def _open_health_url(url: str):
    return _build_http_only_opener().open(url, timeout=5)

def main(url: str = DEFAULT_URL) -> int:
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        return 1
    try:
        with _open_health_url(url) as response:
            body = response.read()
    except Exception:
        return 1
    return 0 if body else 1
'''

_EXPLICIT_SCHEME_GUARD_SOURCE = '''
import urllib.parse
import urllib.request

def main(url: str = DEFAULT_URL) -> int:
    if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
        return 1
    with urllib.request.urlopen(url, timeout=5) as response:
        return 0 if response.read() else 1
'''

_NON_DYNAMIC_HEALTH_SOURCE = '''
import urllib.request

def main() -> int:
    with urllib.request.urlopen("http://127.0.0.1:8099/healthz", timeout=5) as response:
        return 0 if response.read() else 1
'''


def _rule(rule_id: str) -> dict:
    """Return the single packaged rule for one Keyverse source family."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == rule_id]
    assert len(matches) == 1, f"expected one loaded rule for {rule_id}"
    return matches[0]


def _scan(source: str, tmp_path: Path, filename: str, rule_id: str) -> list[dict]:
    """Run the production scanner and isolate one detector family."""
    source_file = tmp_path / filename
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == rule_id
    ]


def test_source_provenance_pins_keyverse_objects() -> None:
    """Record immutable vulnerable and protected-fixed Keyverse source identities."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/keyverse"
    assert _VULNERABLE_HEAD_SHA == "938530663fc9c4129fd309f81f8f44b147728b1e"
    assert _FIXED_HEAD_SHA == "ce207dfd42975db61c82a5963e206fc1db14ac2b"
    assert _VULNERABLE_SCIM_BLOB_SHA == "2cb7609c1bd934670cba1a513f64908f8225601f"
    assert _FIXED_SCIM_BLOB_SHA == "4c0b9fbca9d54a9c2237baf3879512ba17a4295d"
    assert _VULNERABLE_HEALTH_BLOB_SHA == "4284510ce94ac7148aeaec860b69b65d538b4acb"
    assert _FIXED_HEALTH_BLOB_SHA == "fd33ac621a2c7c86553ee3049e98d7ac91189186"


def test_scim_rule_detects_put_without_tombstone_guard() -> None:
    """Detect full replacement of a merged user without an immutable-state check."""
    rule = _rule(_SCIM_RULE_ID)
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_SCIM_SOURCE)


def test_scim_rule_ignores_reviewed_tombstone_guard() -> None:
    """Keep the protected Keyverse tombstone and lock repair negative."""
    assert not _rule(_SCIM_RULE_ID)["pattern"].search(_FIXED_SCIM_SOURCE)


def test_scim_rule_ignores_alternate_merged_state_guard() -> None:
    """Allow an equivalent explicit merged-state check before full replacement."""
    assert not _rule(_SCIM_RULE_ID)["pattern"].search(_ALTERNATE_SCIM_GUARD_SOURCE)


def test_health_rule_detects_dynamic_urlopen_without_scheme_guard() -> None:
    """Detect a dynamic health URL passed to the default multi-protocol opener."""
    rule = _rule(_HEALTH_RULE_ID)
    assert rule["severity"] == "MEDIUM"
    assert rule["pattern"].search(_VULNERABLE_HEALTH_SOURCE)


def test_health_rule_ignores_reviewed_http_only_opener() -> None:
    """Keep the protected Keyverse HTTP(S)-only opener repair negative."""
    assert not _rule(_HEALTH_RULE_ID)["pattern"].search(_FIXED_HEALTH_SOURCE)


def test_health_rule_ignores_explicit_initial_scheme_guard() -> None:
    """Allow a direct HTTP(S) scheme allow-list before dynamic urlopen."""
    assert not _rule(_HEALTH_RULE_ID)["pattern"].search(_EXPLICIT_SCHEME_GUARD_SOURCE)


def test_health_rule_ignores_literal_local_url() -> None:
    """Do not classify a literal local self-probe as a dynamic URL sink."""
    assert not _rule(_HEALTH_RULE_ID)["pattern"].search(_NON_DYNAMIC_HEALTH_SOURCE)


def test_production_scanner_emits_normalized_scim_finding(tmp_path: Path) -> None:
    """Exercise the tombstone detector through the production scanner."""
    findings = _scan(_VULNERABLE_SCIM_SOURCE, tmp_path, "scim.py", _SCIM_RULE_ID)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "high"
    assert finding["source"] == "appguardrail-rule"
    assert "CWE-841 - Improper Enforcement of Behavioral Workflow" in finding["cwe"]


def test_production_scanner_emits_normalized_health_finding(tmp_path: Path) -> None:
    """Exercise the dynamic-health-URL detector through the production scanner."""
    findings = _scan(
        _VULNERABLE_HEALTH_SOURCE,
        tmp_path,
        "healthcheck.py",
        _HEALTH_RULE_ID,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "MEDIUM"
    assert finding["confidence"] == "medium"
    assert finding["source"] == "appguardrail-rule"
    assert "CWE-918 - Server-Side Request Forgery (SSRF)" in finding["cwe"]


def test_production_scanner_keeps_both_reviewed_fixes_clean(tmp_path: Path) -> None:
    """Keep both protected Keyverse repairs clean through production scanning."""
    assert _scan(_FIXED_SCIM_SOURCE, tmp_path, "scim.py", _SCIM_RULE_ID) == []
    assert _scan(_FIXED_HEALTH_SOURCE, tmp_path, "healthcheck.py", _HEALTH_RULE_ID) == []
