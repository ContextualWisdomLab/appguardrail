"""Source-authoritative RED tests for Rust auth secrets sourced from raw env."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "rust-auth-secret-raw-env-runtime-source"
_SOURCE_REPOSITORY = "ContextualWisdomLab/wardnet"
_VULNERABLE_HEAD_SHA = "867d3186652bca1277aa9f08b2d312bbd71e0beb"
_VULNERABLE_BLOB_SHA = "15ac355b052a38daac13c36ad0a5fbac5443249e"
_FIXED_HEAD_SHA = "ab294c4cb2cc25f2369cf203dc81a65ec071dda7"
_FIXED_BLOB_SHA = "fce07f799369607771ad6f5b474c94d7df9bb708"

_VULNERABLE_SINGLE_TOKEN = '''
let config = AppConfig {
    admin_token: std::env::var("ADMIN_TOKEN").ok(),
    state_path: std::env::var("WAF_IDS_STATE_PATH").ok().map(PathBuf::from),
    dnsbl_origin: "dnsbl.local".to_string(),
    event_limit: 1000,
};
'''

_VULNERABLE_RBAC_TOKENS = '''
let admin_tokens = parse_admin_tokens(
    &std::env::var("ADMIN_TOKENS").unwrap_or_default(),
);
let state = AppState::load(config).await?.with_admin_tokens(admin_tokens);
'''

_FIXED_SOURCE = '''
let credentials = CredentialRegistry::bootstrap_secrets(
    credentials_path.as_deref(),
    std::env::var("ADMIN_TOKEN").ok(),
    std::env::var("ADMIN_TOKENS").ok(),
)?;
let config = AppConfig {
    admin_token: credentials
        .get_credential(CRED_ADMIN_TOKEN)
        .map(str::to_owned),
    state_path: std::env::var("WAF_IDS_STATE_PATH").ok().map(PathBuf::from),
    dnsbl_origin: "dnsbl.local".to_string(),
    event_limit: 1000,
};
let admin_tokens = parse_admin_tokens(
    credentials
        .get_credential(CRED_ADMIN_TOKENS)
        .unwrap_or_default(),
);
'''

_NON_SECRET_OPERATIONAL_ENV = '''
let bind_addr = std::env::var("BIND_ADDR")
    .unwrap_or_else(|_| "127.0.0.1:8080".to_string());
let event_limit = std::env::var("EVENT_LIMIT").ok();
'''

_BOOTSTRAP_ONLY_ENV = '''
let registry = CredentialRegistry::bootstrap_secrets(
    None,
    std::env::var("ADMIN_TOKEN").ok(),
    std::env::var("ADMIN_TOKENS").ok(),
)?;
serve(registry).await
'''


def _rule():
    """Return the one packaged runtime env-secret rule under test."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Execute the production scanner on one Rust source fixture."""
    source_file = tmp_path / "lib.rs"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_is_explicit_and_immutable() -> None:
    """Pin Wardnet's pre-registry source and reviewed credential-registry repair."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/wardnet"
    assert _VULNERABLE_HEAD_SHA == "867d3186652bca1277aa9f08b2d312bbd71e0beb"
    assert _VULNERABLE_BLOB_SHA == "15ac355b052a38daac13c36ad0a5fbac5443249e"
    assert _FIXED_HEAD_SHA == "ab294c4cb2cc25f2369cf203dc81a65ec071dda7"
    assert _FIXED_BLOB_SHA == "fce07f799369607771ad6f5b474c94d7df9bb708"


def test_rule_detects_direct_admin_token_runtime_env_source() -> None:
    """Detect ADMIN_TOKEN flowing directly from std::env::var into auth config."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_SINGLE_TOKEN)


def test_rule_detects_direct_admin_tokens_parser_env_source() -> None:
    """Detect ADMIN_TOKENS read directly from env at the runtime auth parser."""
    assert _rule()["pattern"].search(_VULNERABLE_RBAC_TOKENS)


def test_rule_declares_tight_rust_auth_prefilters() -> None:
    """Avoid evaluating the multiline rule outside the exact Wardnet-like contract."""
    assert _rule()["required_substrings"] == (
        "std::env::var",
        "ADMIN_TOKEN",
        "admin_token",
    )


def test_rule_ignores_credential_registry_bootstrap_and_runtime_lookup() -> None:
    """Do not flag env when it is only bootstrap transport into the secret registry."""
    assert not _rule()["pattern"].search(_FIXED_SOURCE)
    assert not _rule()["pattern"].search(_BOOTSTRAP_ONLY_ENV)


def test_rule_ignores_non_secret_operational_environment() -> None:
    """Do not generalize the organization secret boundary to ordinary config."""
    assert not _rule()["pattern"].search(_NON_SECRET_OPERATIONAL_ENV)


def test_scan_file_emits_cwe_526_finding(tmp_path: Path) -> None:
    """Verify production scanning emits the source-backed environment-secret weakness."""
    findings = _scan(_VULNERABLE_SINGLE_TOKEN, tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["confidence"] == "high"
    assert any(reference.startswith("CWE-526") for reference in finding["cwe"])


def test_scan_file_keeps_reviewed_fix_clean(tmp_path: Path) -> None:
    """Keep the reviewed credential-registry repair clean in production scan."""
    assert _scan(_FIXED_SOURCE, tmp_path) == []
