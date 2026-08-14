"""Source-authoritative regressions for JSON password type validation."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_SIGNUP_RULE_ID = "javascript-json-password-string-coercion-before-hash"
_VERIFY_RULE_ID = "javascript-json-password-untyped-verify-fallback"
_SOURCE_REPOSITORY = "ContextualWisdomLab/scopeweave"
_VULNERABLE_HEAD_SHA = "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
_VULNERABLE_APP_BLOB_SHA = "926d528d17b7ae39ab89001657a21f7ef30af743"
_VULNERABLE_AUTH_BLOB_SHA = "3d0b171fb2d5049f010c405f051409a849840b26"
_FIXED_HEAD_SHA = "bd9a51584f1cf37f4f4446022a90775a20152edf"
_FIXED_APP_BLOB_SHA = "13d95e5dfa0719451a5b4a6d952467994172b79a"
_FIXED_AUTH_BLOB_SHA = "5893dd511f5a73fa8e595728e68f6e84d4011c45"

_VULNERABLE_SIGNUP_SOURCE = """
app.post('/api/auth/signup', async (c) => {
  const { email, password, name } = await c.req.json().catch(() => ({}));
  if (!email || !password || String(password).length < 8) {
    return c.json({ error: 'email and password (min 8 chars) required' }, 400);
  }
  const passwordHash = hashPassword(password);
  return c.json({ passwordHash });
});
"""

_FIXED_SIGNUP_SOURCE = """
app.post('/api/auth/signup', async (c) => {
  const { email, password, name } = await c.req.json().catch(() => ({}));
  if (!email || typeof password !== 'string' || password.length < 8) {
    return c.json({ error: 'email and password (min 8 chars) required' }, 400);
  }
  const passwordHash = hashPassword(password);
  return c.json({ passwordHash });
});
"""

_VULNERABLE_LOGIN_SOURCE = """
app.post('/api/auth/login', async (c) => {
  const { email, password } = await c.req.json().catch(() => ({}));
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email || '');
  if (!u || !verifyPassword(password || '', u.password_hash)) {
    return c.json({ error: 'invalid credentials' }, 401);
  }
  return c.json({ ok: true });
});
"""

_FIXED_LOGIN_SOURCE = """
app.post('/api/auth/login', async (c) => {
  const { email, password } = await c.req.json().catch(() => ({}));
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email || '');
  if (!u || typeof password !== 'string' || !verifyPassword(password, u.password_hash)) {
    return c.json({ error: 'invalid credentials' }, 401);
  }
  return c.json({ ok: true });
});
"""

_TYPED_SCHEMA_SOURCE = """
app.post('/api/auth/signup', async (c) => {
  const body = PasswordSchema.parse(await c.req.json());
  if (body.password.length < 8) return c.json({ error: 'short' }, 400);
  return c.json({ passwordHash: hashPassword(body.password) });
});
"""

_NON_PASSWORD_COERCION_SOURCE = """
app.post('/api/profile', async (c) => {
  const { page } = await c.req.json().catch(() => ({}));
  if (String(page).length > 8) return c.json({ error: 'page too long' }, 400);
  return c.json({ page: String(page) });
});
"""


def _rule(rule_id: str) -> dict:
    """Return one packaged rule by identity."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == rule_id]
    assert len(matches) == 1, f"expected one loaded rule for {rule_id}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Run the production scanner over a JavaScript source replay."""
    source_file = tmp_path / "app.mjs"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in {_SIGNUP_RULE_ID, _VERIFY_RULE_ID}
    ]


def test_source_provenance_is_explicit_and_immutable() -> None:
    """Pin source repository, vulnerable/fixed revisions, and affected blobs."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/scopeweave"
    assert _VULNERABLE_HEAD_SHA == "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
    assert _VULNERABLE_APP_BLOB_SHA == "926d528d17b7ae39ab89001657a21f7ef30af743"
    assert _VULNERABLE_AUTH_BLOB_SHA == "3d0b171fb2d5049f010c405f051409a849840b26"
    assert _FIXED_HEAD_SHA == "bd9a51584f1cf37f4f4446022a90775a20152edf"
    assert _FIXED_APP_BLOB_SHA == "13d95e5dfa0719451a5b4a6d952467994172b79a"
    assert _FIXED_AUTH_BLOB_SHA == "5893dd511f5a73fa8e595728e68f6e84d4011c45"


def test_signup_rule_detects_string_coercion_before_password_hash() -> None:
    """Detect raw JSON password coercion used as a substitute for type checking."""
    rule = _rule(_SIGNUP_RULE_ID)
    assert rule["severity"] == "MEDIUM"
    assert rule["pattern"].search(_VULNERABLE_SIGNUP_SOURCE)


def test_verify_rule_detects_truthy_fallback_before_password_verification() -> None:
    """Detect an untyped JSON password forwarded through a truthy fallback."""
    rule = _rule(_VERIFY_RULE_ID)
    assert rule["severity"] == "MEDIUM"
    assert rule["pattern"].search(_VULNERABLE_LOGIN_SOURCE)


def test_rules_declare_bounded_prefilters() -> None:
    """Avoid multiline matching on files outside the observed auth contracts."""
    assert _rule(_SIGNUP_RULE_ID)["required_substrings"] == (
        "c.req.json",
        "String(password)",
        "hashPassword",
    )
    assert _rule(_VERIFY_RULE_ID)["required_substrings"] == (
        "c.req.json",
        "verifyPassword",
        "password ||",
    )


def test_rules_ignore_explicit_string_type_validation() -> None:
    """Keep the reviewed fail-closed type guards clean."""
    assert not _rule(_SIGNUP_RULE_ID)["pattern"].search(_FIXED_SIGNUP_SOURCE)
    assert not _rule(_VERIFY_RULE_ID)["pattern"].search(_FIXED_LOGIN_SOURCE)


def test_rules_ignore_schema_typed_password_flow() -> None:
    """Do not flag an upstream schema parse that yields a typed password."""
    assert not _rule(_SIGNUP_RULE_ID)["pattern"].search(_TYPED_SCHEMA_SOURCE)
    assert not _rule(_VERIFY_RULE_ID)["pattern"].search(_TYPED_SCHEMA_SOURCE)


def test_rules_ignore_non_password_string_coercion() -> None:
    """Require the source-derived password and crypto-helper boundary."""
    assert not _rule(_SIGNUP_RULE_ID)["pattern"].search(_NON_PASSWORD_COERCION_SOURCE)
    assert not _rule(_VERIFY_RULE_ID)["pattern"].search(_NON_PASSWORD_COERCION_SOURCE)


def test_scan_file_emits_normalized_type_validation_findings(tmp_path: Path) -> None:
    """Exercise the production scanner for both source-derived variants."""
    findings = _scan(_VULNERABLE_SIGNUP_SOURCE + _VULNERABLE_LOGIN_SOURCE, tmp_path)
    assert {finding["rule_id"] for finding in findings} == {
        _SIGNUP_RULE_ID,
        _VERIFY_RULE_ID,
    }
    for finding in findings:
        assert finding["severity"] == "MEDIUM"
        assert finding["source"] == "appguardrail-rule"
        assert finding["confidence"] == "high"
        assert finding["cwe"] == (
            "CWE-1287 - Improper Validation of Specified Type of Input",
        )


def test_scan_file_does_not_flag_reviewed_fixes(tmp_path: Path) -> None:
    """Keep both fixed auth source shapes clean through production scan."""
    assert _scan(_FIXED_SIGNUP_SOURCE + _FIXED_LOGIN_SOURCE, tmp_path) == []
