"""Exact Naruon source replay for URL-path canonicalization-order detection."""

from pathlib import Path

from scanner.cli import appguardrail as ag

RULE_ID = "python-url-path-traversal-validate-before-canonicalize"
SOURCE_REPOSITORY = "ContextualWisdomLab/naruon"
VULNERABLE_HEAD_SHA = "fedf06b7eec7e6cd4e1a8b27b864d5152ff98b84"
VULNERABLE_BLOB_SHA = "d12c23a46afc6f2f6a38321e326e64cf7f3a1436"
FIXED_HEAD_SHA = "0547162be7fdc958e375e69b05e0e3b1c26e1074"

VULNERABLE_SOURCE = '''
def _txt_context_path(records: list[str]) -> str | None:
    """Extract and validate the RFC 6764 Section 6 TXT ``path`` hint."""
    for record in records:
        for part in record.split(";"):
            key, _, value = part.strip().partition("=")
            if key.strip().lower() != "path":
                continue
            path = value.strip()
            decoded_path = path
            for _ in range(_MAX_CONTEXT_PATH_DECODE_ROUNDS):
                next_path = unquote(decoded_path)
                if next_path == decoded_path:
                    break
                decoded_path = next_path
            else:
                if unquote(decoded_path) != decoded_path:
                    continue
            if (
                decoded_path.startswith("/")
                and "://" not in decoded_path
                and "\\\\" not in decoded_path
                and "?" not in decoded_path
                and "#" not in decoded_path
                and all(
                    segment not in {".", ".."} for segment in decoded_path.split("/")
                )
                and all(ord(ch) >= 32 and ord(ch) != 127 for ch in decoded_path)
            ):
                return path
    return None
'''

FIXED_SOURCE = VULNERABLE_SOURCE.replace("return path", "return decoded_path")


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Execute the packaged detector through the production file scanner."""
    target = tmp_path / "carddav_discovery.py"
    target.write_text(source, encoding="utf-8")
    ag._RULES_CACHE.clear()
    ag._LAST_SCAN_RULES_ID = None
    return [
        finding
        for finding in ag._scan_file(target, tmp_path)
        if finding["rule_id"] == RULE_ID
    ]


def test_exact_historical_source_detects_validated_decoded_but_returned_raw_path(
    tmp_path: Path,
) -> None:
    """Detect the exact representation mismatch collected from Naruon PR #1206."""
    findings = _scan(VULNERABLE_SOURCE, tmp_path)

    assert len(findings) == 1
    assert findings[0]["line"] == 9
    assert findings[0]["snippet"] == "path = value.strip()"


def test_exact_fixed_source_returns_the_same_canonical_value_that_was_validated(
    tmp_path: Path,
) -> None:
    """Do not flag the reviewed fix that returns ``decoded_path``."""
    assert _scan(FIXED_SOURCE, tmp_path) == []


def test_source_provenance_is_explicit_and_immutable() -> None:
    """Pin the repository, vulnerable source identity, and reviewed fixed head."""
    assert SOURCE_REPOSITORY == "ContextualWisdomLab/naruon"
    assert VULNERABLE_HEAD_SHA == "fedf06b7eec7e6cd4e1a8b27b864d5152ff98b84"
    assert VULNERABLE_BLOB_SHA == "d12c23a46afc6f2f6a38321e326e64cf7f3a1436"
    assert FIXED_HEAD_SHA == "0547162be7fdc958e375e69b05e0e3b1c26e1074"
