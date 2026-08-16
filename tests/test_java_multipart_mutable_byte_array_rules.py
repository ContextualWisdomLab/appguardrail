"""Source-authoritative regressions for mutable MultipartFile byte-array exposure."""

from __future__ import annotations

import hashlib
from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "java-multipart-mutable-byte-array-exposure"
_SOURCE_REPOSITORY = "ContextualWisdomLab/clearfolio"
_VULNERABLE_HEAD_SHA = "a44209e2cb743393ff41b17a59ba21fa546473ab"
_VULNERABLE_BLOB_SHA = "7bd4d0df252a9ecfde89b1b87cafb716130f8a69"
_FIXED_HEAD_SHA = "ae0bc74d3ccc811da6d117443663170b2df189c4"
_FIXED_BLOB_SHA = "c47cdd80a786bddddaacd2bb05a82b8b37e61114"
_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_VULNERABLE_FIXTURE = (
    _FIXTURE_DIR / "clearfolio_in_memory_multipart_file_vulnerable.java"
)
_FIXED_FIXTURE = _FIXTURE_DIR / "clearfolio_in_memory_multipart_file_fixed.java"


def _git_blob_sha(path: Path) -> str:
    """Return the immutable Git object identity for one source fixture."""
    payload = path.read_bytes()
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _rule() -> dict:
    """Return the single packaged mutable-byte-array detector."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Execute the production scanner and isolate this detector's findings."""
    source_file = tmp_path / "InMemoryMultipartFile.java"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def _constructor_alias_only() -> str:
    """Retain a caller-owned array while returning a defensive copy."""
    return _FIXED_FIXTURE.read_text(encoding="utf-8").replace(
        "this.content = content == null ? new byte[0] : "
        "Arrays.copyOf(content, content.length);",
        "this.content = content == null ? new byte[0] : content;",
    )


def _getter_exposure_only() -> str:
    """Copy constructor input while returning the private array reference."""
    return _FIXED_FIXTURE.read_text(encoding="utf-8").replace(
        "return Arrays.copyOf(content, content.length);",
        "return content;",
    )


def _clone_based_safe_source() -> str:
    """Use Java array cloning at both mutable trust boundaries."""
    return _FIXED_FIXTURE.read_text(encoding="utf-8").replace(
        "Arrays.copyOf(content, content.length)",
        "content.clone()",
    )


def _unrelated_byte_array_holder() -> str:
    """Return an internal byte array outside the MultipartFile contract."""
    return """
public final class DigestCache {
    private final byte[] content;

    public DigestCache(byte[] content) {
        this.content = content;
    }

    public byte[] getBytes() {
        return content;
    }
}
"""


def _new_array_return_source() -> str:
    """Return newly allocated bytes rather than an internal mutable field."""
    return """
import org.springframework.web.multipart.MultipartFile;

public final class GeneratedMultipartFile implements MultipartFile {
    private final byte[] content = new byte[0];

    @Override
    public byte[] getBytes() {
        return new byte[] {1, 2, 3};
    }
}
"""


def test_source_provenance_is_exact_and_immutable() -> None:
    """Pin the collected vulnerable and reviewed fixed Clearfolio objects."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/clearfolio"
    assert _VULNERABLE_HEAD_SHA == "a44209e2cb743393ff41b17a59ba21fa546473ab"
    assert _FIXED_HEAD_SHA == "ae0bc74d3ccc811da6d117443663170b2df189c4"
    assert _git_blob_sha(_VULNERABLE_FIXTURE) == _VULNERABLE_BLOB_SHA
    assert _git_blob_sha(_FIXED_FIXTURE) == _FIXED_BLOB_SHA


def test_packaged_rule_detects_exact_clearfolio_aliasing_regression() -> None:
    """Detect the exact source that removed both defensive copies."""
    rule = _rule()
    source = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(source)


def test_packaged_rule_declares_bounded_prefilters() -> None:
    """Avoid multiline evaluation outside Java MultipartFile implementations."""
    assert _rule()["required_substrings"] == (
        "implements MultipartFile",
        "private final byte[]",
        "getBytes",
    )


def test_packaged_rule_detects_constructor_aliasing_independently() -> None:
    """Flag retention of caller-owned bytes even when the getter copies."""
    assert _rule()["pattern"].search(_constructor_alias_only())


def test_packaged_rule_detects_internal_array_return_independently() -> None:
    """Flag a direct getter return even when constructor input is copied."""
    assert _rule()["pattern"].search(_getter_exposure_only())


def test_packaged_rule_ignores_exact_defensive_copy_fix() -> None:
    """Keep the reviewed Arrays.copyOf boundary clean."""
    source = _FIXED_FIXTURE.read_text(encoding="utf-8")
    assert not _rule()["pattern"].search(source)


def test_packaged_rule_accepts_clone_based_defensive_copy() -> None:
    """Accept equivalent array cloning at both boundaries."""
    assert not _rule()["pattern"].search(_clone_based_safe_source())


def test_packaged_rule_ignores_unrelated_array_holder() -> None:
    """Require the Spring MultipartFile product boundary."""
    assert not _rule()["pattern"].search(_unrelated_byte_array_holder())


def test_packaged_rule_ignores_newly_allocated_getter_result() -> None:
    """Do not flag a getter that returns fresh bytes."""
    assert not _rule()["pattern"].search(_new_array_return_source())


def test_scan_file_emits_normalized_high_integrity_finding(tmp_path: Path) -> None:
    """Verify production scanner evidence for the exact vulnerable replay."""
    source = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")
    findings = _scan(source, tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    expected_line = next(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if line.startswith("public final class InMemoryMultipartFile")
    )
    assert finding["line"] == expected_line
    assert finding["file"] == "InMemoryMultipartFile.java"
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["confidence"] == "high"
    assert finding["category"] == "misconfig"
    assert finding["cwe"] == (
        "CWE-374 - Passing Mutable Objects to an Untrusted Method",
        "CWE-375 - Returning a Mutable Object to an Untrusted Caller",
    )
    assert finding["owasp"] == (
        "OWASP A08:2021 - Software and Data Integrity Failures",
    )


def test_scan_file_keeps_reviewed_fix_clean(tmp_path: Path) -> None:
    """Verify the exact reviewed fixed source remains finding-free."""
    source = _FIXED_FIXTURE.read_text(encoding="utf-8")
    assert _scan(source, tmp_path) == []
