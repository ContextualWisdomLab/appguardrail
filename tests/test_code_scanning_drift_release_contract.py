"""Release-facing contracts for live Code Scanning drift detection."""

from __future__ import annotations

from pathlib import Path

import appguardrail_core
from scripts.ci import commercial_readiness_loop


ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = ROOT / "docs" / "code-scanning-analysis-drift.md"
CHANGELOG_PATH = ROOT / "CHANGELOG.d" / "862-code-scanning-analysis-drift.md"


def test_code_scanning_core_is_available_through_public_package_api() -> None:
    """Modular consumers must not import private implementation paths."""
    expected = {
        "AnalysisEvidence",
        "AnalysisIdentity",
        "AnalysisSnapshot",
        "DriftAssessment",
        "build_code_scanning_snapshot",
        "compare_code_scanning_snapshots",
        "normalize_code_scanning_analysis",
    }

    assert expected <= set(appguardrail_core.__all__)
    assert all(hasattr(appguardrail_core, name) for name in expected)


def test_operator_documentation_explains_evidence_and_permission_boundaries() -> None:
    """Operators must understand clean, drift, unknown, and least-privilege states."""
    text = DOC_PATH.read_text(encoding="utf-8")

    assert "clean" in text
    assert "drift" in text
    assert "unknown" in text
    assert "Code scanning alerts: read" in text
    assert "Pull requests: read" in text
    assert "refs/pull/<number>/merge" in text
    assert "tool.name" in text
    assert "tool_name" in text
    assert "github-actions-sarif-missing-pull-request-trigger" in text
    assert "403" in text and "404" in text and "503" in text
    assert "exact head" in text.lower()
    assert "naruon" in text


def test_changelog_fragment_describes_live_state_detection_without_overclaiming() -> None:
    """Release notes must distinguish confirmed drift from unknown GitHub state."""
    text = CHANGELOG_PATH.read_text(encoding="utf-8")

    assert "### Added" in text
    assert "live GitHub Code Scanning" in text
    assert "fail-closed" in text
    assert "exact-head" in text
    assert "unknown" in text


def test_completed_gap_is_removed_and_next_reviewed_gap_remains() -> None:
    """The hourly loop must advance only after this implementation slice lands."""
    gap_ids = [gap.id for gap in commercial_readiness_loop.COMMERCIAL_GAPS]

    assert "github-code-scanning-analysis-drift" not in gap_ids
    assert gap_ids[0] == "openssf-best-practices-evidence"
    assert "enterprise-retention-audit-policy" in gap_ids
