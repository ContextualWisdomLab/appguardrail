"""Source-authoritative regressions for unvalidated password types at scrypt sinks."""

import hashlib
import json
from pathlib import Path
import urllib.request

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "javascript-auth-scrypt-unvalidated-password-type"
_RULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scanner"
    / "rules"
    / "javascript_scrypt_password_type.yml"
)
_SOURCE_REPOSITORY = "ContextualWisdomLab/scopeweave"
_SOURCE_PATH = "server/auth.mjs"
_VULNERABLE_HEAD_SHA = "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
_VULNERABLE_BLOB_SHA = "3d0b171fb2d5049f010c405f051409a849840b26"
_FIXED_HEAD_SHA = "644e9fc5cb3adfb96e2948152f92c61f8661e6d3"
_FIXED_BLOB_SHA = "a16a7281b3da4683eea85263fea929dd9483e9df"
_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_VULNERABLE_FIXTURE = _FIXTURE_DIR / "scopeweave_scrypt_type_vulnerable.mjs"
_FIXED_FIXTURE = _FIXTURE_DIR / "scopeweave_scrypt_type_fixed.mjs"

_GUARD_AFTER_SINK = """
import { scryptSync } from 'node:crypto';
export function verifyPassword(pw, stored) {
  const test = scryptSync(pw, 'salt', 64);
  if (typeof pw !== 'string') return false;
  return test.length > 0;
}
"""

_SAFE_NORMALIZATION = """
import { scryptSync } from 'node:crypto';
export function hashPassword(pw) {
  const password = typeof pw === 'string' ? pw : '';
  return scryptSync(password, 'salt', 64).toString('hex');
}
"""

_TYPESCRIPT_PARAMETER = """
import { scryptSync } from 'node:crypto';
export function hashPassword(pw: unknown): string {
  return scryptSync(pw, 'salt', 64).toString('hex');
}
"""

_NESTED_BLOCK_BEFORE_SINK = """
import { scryptSync } from 'node:crypto';
export function verifyPassword(pw, stored) {
  if (stored) {
    audit(stored);
  }
  return scryptSync(pw, 'salt', 64).length > 0;
}
"""

_NON_TERMINATING_TYPE_COMPARISON = """
import { scryptSync } from 'node:crypto';
export function verifyPassword(pw, stored) {
  if (typeof pw !== 'string') console.warn('unexpected password type');
  return scryptSync(pw, 'salt', 64).length > 0;
}
"""

_NON_PASSWORD_SCRYPT = """
import { scryptSync } from 'node:crypto';
export function deriveKey(secretBytes) {
  return scryptSync(secretBytes, 'salt', 64);
}
"""


def _git_blob_sha(path: Path) -> str:
    """Return the Git blob object ID for one immutable replay fixture."""
    payload = path.read_bytes()
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _github_path_blob_sha(head_sha: str) -> str:
    """Resolve the pinned ScopeWeave path to its Git blob through GitHub's tree API."""
    commit_url = (
        "https://api.github.com/repos/"
        f"{_SOURCE_REPOSITORY}/git/commits/{head_sha}"
    )
    request = urllib.request.Request(
        commit_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AppGuardrail-source-provenance-test",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        commit_payload = json.load(response)

    tree_sha = commit_payload["tree"]["sha"]
    tree_url = (
        "https://api.github.com/repos/"
        f"{_SOURCE_REPOSITORY}/git/trees/{tree_sha}?recursive=1"
    )
    request = urllib.request.Request(
        tree_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AppGuardrail-source-provenance-test",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        tree_payload = json.load(response)

    matches = [
        entry["sha"]
        for entry in tree_payload["tree"]
        if entry.get("path") == _SOURCE_PATH and entry.get("type") == "blob"
    ]
    assert matches == [matches[0]], f"expected exactly one {_SOURCE_PATH} blob"
    return matches[0]


def _rules() -> tuple[dict, ...]:
    """Return the two packaged source-shape variants for this weakness family."""
    matches = tuple(rule for rule in SCAN_RULES if rule["id"] == _RULE_ID)
    assert len(matches) == 2, f"expected two loaded variants for {_RULE_ID}"
    return matches


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Run the production scanner and isolate this detector family."""
    source_file = tmp_path / "auth.mjs"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_is_exact_and_immutable() -> None:
    """Bind each ScopeWeave commit/path and replay fixture to the same Git blob."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/scopeweave"
    assert _VULNERABLE_HEAD_SHA == "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
    assert _FIXED_HEAD_SHA == "644e9fc5cb3adfb96e2948152f92c61f8661e6d3"
    assert _github_path_blob_sha(_VULNERABLE_HEAD_SHA) == _VULNERABLE_BLOB_SHA
    assert _github_path_blob_sha(_FIXED_HEAD_SHA) == _FIXED_BLOB_SHA
    assert _git_blob_sha(_VULNERABLE_FIXTURE) == _VULNERABLE_BLOB_SHA
    assert _git_blob_sha(_FIXED_FIXTURE) == _FIXED_BLOB_SHA


def test_rule_file_declares_non_executable_detection_data_boundary() -> None:
    """Keep model-backed checks from mistaking detector signatures for runtime code."""
    source = _RULE_PATH.read_text(encoding="utf-8")
    assert "# AppGuardrail detector artifact: non-executable SAST signature data." in source
    assert (
        "# Vulnerable source shapes below describe detection targets, not AppGuardrail runtime code."
        in source
    )


def test_packaged_variants_detect_both_scopeweave_password_scrypt_sinks() -> None:
    """Detect unguarded password hashing and verification in the source replay."""
    source = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")
    rules = _rules()
    assert all(rule["severity"] == "HIGH" for rule in rules)
    assert sum(bool(rule["pattern"].search(source)) for rule in rules) == 2


def test_packaged_variants_use_parser_safe_bounded_prefilters() -> None:
    """Keep the expensive function-bounded expressions off unrelated files."""
    prefilters = {rule["required_substrings"] for rule in _rules()}
    assert prefilters == {
        ("scryptSync(", "function hashPassword"),
        ("scryptSync(", "function verifyPassword"),
    }


def test_packaged_variants_ignore_reviewed_type_safe_source() -> None:
    """Keep the exact reviewed ScopeWeave repair negative."""
    source = _FIXED_FIXTURE.read_text(encoding="utf-8")
    assert all(not rule["pattern"].search(source) for rule in _rules())


def test_packaged_hash_variant_ignores_safe_local_normalization() -> None:
    """Allow an explicit string-or-empty normalization before the scrypt sink."""
    assert all(not rule["pattern"].search(_SAFE_NORMALIZATION) for rule in _rules())


def test_packaged_verify_variant_detects_guard_that_occurs_too_late() -> None:
    """A type check after scrypt cannot prevent the unsupported input call."""
    assert any(rule["pattern"].search(_GUARD_AFTER_SINK) for rule in _rules())


def test_packaged_variants_ignore_non_password_scrypt_helper() -> None:
    """Do not classify arbitrary key derivation as an authentication boundary."""
    assert all(not rule["pattern"].search(_NON_PASSWORD_SCRYPT) for rule in _rules())


def test_scan_file_detects_supported_structural_vulnerability_variants(
    tmp_path: Path,
) -> None:
    """Keep TypeScript, nested blocks, and non-terminating checks visible to production scan."""
    for source in (
        _TYPESCRIPT_PARAMETER,
        _NESTED_BLOCK_BEFORE_SINK,
        _NON_TERMINATING_TYPE_COMPARISON,
    ):
        findings = _scan(source, tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"


def test_scan_file_emits_two_normalized_high_findings(tmp_path: Path) -> None:
    """Exercise both vulnerable functions through the exact production scanner."""
    source = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")
    findings = _scan(source, tmp_path)

    assert len(findings) == 2
    expected_lines = {
        source.splitlines().index("export function hashPassword(pw) {") + 1,
        source.splitlines().index("export function verifyPassword(pw, stored) {") + 1,
    }
    assert {finding["line"] for finding in findings} == expected_lines
    assert all(finding["severity"] == "HIGH" for finding in findings)
    assert all(finding["confidence"] == "high" for finding in findings)
    assert all(finding["source"] == "appguardrail-rule" for finding in findings)
    assert all(
        "CWE-1287 - Improper Validation of Specified Type of Input" in finding["cwe"]
        for finding in findings
    )
    assert all("CWE-248" not in finding["cwe"] for finding in findings)


def test_scan_file_does_not_flag_reviewed_fix(tmp_path: Path) -> None:
    """Keep the immutable reviewed repair clean through production scanning."""
    source = _FIXED_FIXTURE.read_text(encoding="utf-8")
    assert _scan(source, tmp_path) == []
