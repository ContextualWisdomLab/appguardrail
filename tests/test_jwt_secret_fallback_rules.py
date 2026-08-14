"""Source-authoritative regression tests for hardcoded JWT secret fallbacks."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "javascript-jwt-hardcoded-secret-fallback"
_SOURCE_REPOSITORY = "ContextualWisdomLab/scopeweave"
_VULNERABLE_HEAD_SHA = "7a6ff367a43a8711fc97d124d0bed5dad8941b7d"
_VULNERABLE_BLOB_SHA = "3d0b171fb2d5049f010c405f051409a849840b26"
_FIXED_HEAD_SHA = "37289072bd3039fcca3f113e5707e7a278a3a9b1"
_FIXED_BLOB_SHA = "5893dd511f5a73fa8e595728e68f6e84d4011c45"

_VULNERABLE_SOURCE = """
import { createHmac } from 'node:crypto';

const SECRET = process.env.SCOPEWEAVE_JWT_SECRET || 'dev-insecure-secret-change-me';
if (SECRET === 'dev-insecure-secret-change-me') {
  console.warn('[auth] INSECURE dev JWT secret in use');
}

export function signToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}
"""

_FIXED_SOURCE = """
import { createHmac } from 'node:crypto';

const SECRET = process.env.SCOPEWEAVE_JWT_SECRET;
if (
  typeof SECRET !== 'string'
  || SECRET.replace(/\\s/g, '').length < 32
  || SECRET.includes('${SCOPEWEAVE_JWT_SECRET')
) {
  throw new Error('SCOPEWEAVE_JWT_SECRET must be configured securely');
}

export function signToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}
"""

_RANDOM_FALLBACK_SOURCE = """
import { createHmac, randomBytes } from 'node:crypto';

const SECRET = process.env.JWT_SECRET || randomBytes(32).toString('hex');

export function signToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  return createHmac('sha256', SECRET).update(JSON.stringify(payload)).digest('base64url');
}
"""

_NON_SIGNING_SOURCE = """
const SECRET = process.env.OPTIONAL_LABEL_SECRET || 'local-label-placeholder';
export function label() {
  return `HS256-${SECRET}`;
}
"""


def _rule():
    """Return the single packaged rule for the exact source-derived slice."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Execute the production scanner and isolate this detector's findings."""
    source_file = tmp_path / "auth.mjs"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_is_explicit_and_immutable() -> None:
    """Pin the vulnerable and fixed ScopeWeave source identities."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/scopeweave"
    assert _VULNERABLE_HEAD_SHA == "7a6ff367a43a8711fc97d124d0bed5dad8941b7d"
    assert _VULNERABLE_BLOB_SHA == "3d0b171fb2d5049f010c405f051409a849840b26"
    assert _FIXED_HEAD_SHA == "37289072bd3039fcca3f113e5707e7a278a3a9b1"
    assert _FIXED_BLOB_SHA == "5893dd511f5a73fa8e595728e68f6e84d4011c45"


def test_packaged_rule_detects_scopeweave_hardcoded_hs256_fallback() -> None:
    """Detect an environment lookup that falls back to a shared signing key."""
    rule = _rule()
    assert rule["severity"] == "CRITICAL"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_packaged_rule_detects_nullish_literal_fallback() -> None:
    """Treat a nullish-coalescing literal fallback as the same key weakness."""
    source = _VULNERABLE_SOURCE.replace(" || ", " ?? ", 1)
    assert _rule()["pattern"].search(source)


def test_packaged_rule_declares_bounded_prefilter() -> None:
    """Skip the multiline signature for files outside the JWT HMAC contract."""
    assert _rule()["required_substrings"] == (
        "process.env",
        "createHmac",
        "HS256",
    )


def test_packaged_rule_ignores_fail_closed_secret_configuration() -> None:
    """Do not flag a required secret that is validated before token signing."""
    assert not _rule()["pattern"].search(_FIXED_SOURCE)


def test_packaged_rule_ignores_runtime_generated_fallback() -> None:
    """Do not classify a random per-process value as a hardcoded key literal."""
    assert not _rule()["pattern"].search(_RANDOM_FALLBACK_SOURCE)


def test_packaged_rule_ignores_literal_not_used_for_signing() -> None:
    """Require an HMAC signing sink rather than any optional secret fallback."""
    assert not _rule()["pattern"].search(_NON_SIGNING_SOURCE)


def test_scan_file_emits_normalized_critical_finding(tmp_path: Path) -> None:
    """Verify the exact production finding envelope for the source replay."""
    findings = _scan(_VULNERABLE_SOURCE, tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["line"] == 4
    assert finding["snippet"].startswith("const SECRET = process.env")
    assert finding["severity"] == "CRITICAL"
    assert finding["category"] == "secrets"
    assert finding["confidence"] == "high"
    assert finding["source"] == "appguardrail-rule"
    assert finding["cwe"] == (
        "CWE-321 - Use of Hard-coded Cryptographic Key",
        "CWE-798 - Use of Hard-coded Credentials",
    )
    assert finding["owasp"] == (
        "OWASP A07:2021 - Identification and Authentication Failures",
    )


def test_scan_file_does_not_flag_reviewed_fix(tmp_path: Path) -> None:
    """Keep the exact fail-closed reviewed source clean through production scan."""
    assert _scan(_FIXED_SOURCE, tmp_path) == []
