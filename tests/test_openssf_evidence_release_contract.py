"""Release, documentation, public API, and autonomous-handoff contracts."""

from __future__ import annotations

from pathlib import Path

from appguardrail_core import (
    OpenSSFEvidence,
    collect_openssf_evidence,
    evidence_to_finding,
    parse_openssf_project_matches,
)
from scripts.ci.commercial_readiness_loop import COMMERCIAL_GAPS


ROOT = Path(__file__).resolve().parents[1]


def test_openssf_evidence_is_available_from_public_core_api() -> None:
    """Standalone and MSA consumers must not import private implementation paths."""
    assert OpenSSFEvidence.__module__ == "appguardrail_core.openssf_evidence"
    assert callable(collect_openssf_evidence)
    assert callable(evidence_to_finding)
    assert callable(parse_openssf_project_matches)


def test_operator_documentation_records_official_and_conservative_semantics() -> None:
    """Beginners must be able to operate the feature without reading source code."""
    documentation = (ROOT / "docs" / "openssf-best-practices-evidence.md").read_text(
        encoding="utf-8"
    )
    documentation_lines = set(documentation.splitlines())

    assert "https://www.bestpractices.dev/projects.json?url=" in documentation
    assert "https://bestpractices.coreinfrastructure.org" in documentation_lines
    assert "in_progress" in documentation
    assert "passing" in documentation
    assert "silver" in documentation
    assert "gold" in documentation
    assert "does not prove" in documentation
    assert "--source-json" in documentation
    assert "buyer-diligence" in documentation
    assert "OpenSSF Best Practices Badge API" in documentation
    assert "OpenSSF Best Practices badge contributors" in documentation
    assert "CC-BY-3.0" in documentation


def test_changelog_fragment_describes_buyer_visible_evidence() -> None:
    """The next release must include the evidence collection and report behavior."""
    changelog = (ROOT / "CHANGELOG.d" / "865-openssf-evidence.md").read_text(
        encoding="utf-8"
    )

    assert "OpenSSF Best Practices" in changelog
    assert "buyer-diligence" in changelog
    assert "unavailable" in changelog
    assert "permission" in changelog


def test_evidence_module_avoids_python_311_only_utc_alias() -> None:
    """The new module remains importable on the package's Python 3.10 surface."""
    source = (ROOT / "appguardrail_core" / "openssf_evidence.py").read_text(
        encoding="utf-8"
    )

    assert "from datetime import UTC" not in source
    assert "timezone.utc" in source


def test_exact_coverage_workflow_tracks_every_openssf_test_surface() -> None:
    """New production code must retain an exact unrounded 100% coverage gate."""
    workflow = (
        ROOT / ".github" / "workflows" / "openssf-evidence-coverage.yml"
    ).read_text(encoding="utf-8")

    assert "appguardrail_core/__init__.py" in workflow
    assert "appguardrail_core/openssf_evidence.py" in workflow
    assert "appguardrail_core/openssf_report.py" in workflow
    for path in (
        "tests/test_openssf_evidence.py",
        "tests/test_openssf_evidence_transport.py",
        "tests/test_openssf_evidence_cli.py",
        "tests/test_openssf_evidence_report.py",
        "tests/test_openssf_evidence_release_contract.py",
        "tests/test_openssf_evidence_coverage_edges.py",
        "tests/test_openssf_evidence_validation_edges.py",
    ):
        assert path in workflow
    assert "python -m scripts.ci.verify_module_coverage" in workflow
    assert "permissions:\n  contents: read" in workflow


def test_commercial_readiness_registry_preserves_the_next_gap_order() -> None:
    """Closing issue #865 makes retention controls the next deterministic slice."""
    gap_ids = tuple(gap.id for gap in COMMERCIAL_GAPS)

    assert gap_ids[:2] == (
        "openssf-best-practices-evidence",
        "enterprise-retention-audit-policy",
    )
