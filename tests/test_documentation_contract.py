"""Contract tests for AppGuardrail's canonical product and detector documentation."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCUMENTS = (
    "DOCUMENTATION.md",
    "docs/PRD.md",
    "docs/TRD.md",
    "ARCHITECTURE.md",
    "docs/UML.md",
    "docs/ERD.md",
    "docs/THREAT_MODEL.md",
    "docs/TEST_STRATEGY.md",
    "docs/OPERABILITY.md",
    "docs/TRACEABILITY.md",
    "docs/adr/README.md",
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    "CHANGELOG.md",
)


def _read(relative_path: str) -> str:
    """Return one repository document as UTF-8 text."""

    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_canonical_detection_documents_exist() -> None:
    """Keep product, technical, detection, and operating memory discoverable."""

    missing = [path for path in REQUIRED_DOCUMENTS if not (ROOT / path).is_file()]
    assert not missing, f"missing canonical documentation: {missing}"


def test_documentation_map_links_cross_cutting_contracts() -> None:
    """Require the documentation map to link every major cross-cutting record."""

    documentation = _read("DOCUMENTATION.md")
    for path in REQUIRED_DOCUMENTS[1:11]:
        assert path in documentation, f"documentation map does not link {path}"


def test_active_pr_detection_claims_are_not_promoted_to_main() -> None:
    """Keep stored-SSRF and issue-obligation work labelled as active PRs."""

    prd = _read("docs/PRD.md")
    traceability = _read("docs/TRACEABILITY.md")
    assert "PR #910" in prd and "not protected-branch behavior" in prd
    assert "PR #911" in prd and "active-PR" in prd
    assert "PR #911 active-PR" in traceability
    assert "must be proven separately from PR #910 prevention" in traceability


def test_structural_rule_fixture_is_not_claimed_as_lightweight_execution() -> None:
    """Prevent Semgrep-style fixtures from becoming false built-in capability claims."""

    prd = _read("docs/PRD.md")
    architecture = _read("ARCHITECTURE.md")
    assert "structural `pattern:`" in prd
    assert "not automatically executable in full" in architecture


def test_adr_index_contains_governing_detector_decisions() -> None:
    """Keep the detector/security architecture decisions indexed."""

    index = _read("docs/adr/README.md")
    for adr in (
        "0001-executable-detector-truth.md",
        "0002-prevention-versus-detection.md",
        "0003-external-engine-provenance.md",
        "0004-tenant-network-boundaries.md",
        "0005-remediation-authority.md",
        "0006-automation-authority.md",
    ):
        assert adr in index, f"ADR index is missing {adr}"
