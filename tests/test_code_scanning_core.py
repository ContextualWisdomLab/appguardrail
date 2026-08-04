"""Regression tests for live GitHub Code Scanning analysis drift comparison."""

from __future__ import annotations

import pytest

from appguardrail_core.code_scanning import (
    AnalysisIdentity,
    build_snapshot,
    compare_snapshots,
    normalize_analysis,
)


def _analysis(
    *,
    analysis_id: int = 1,
    tool_name: str = "Trivy",
    tool_guid: str | None = "trivy-guid",
    category: str = "filesystem",
    analysis_key: str = ".github/workflows/security.yml:scan refs/heads/develop",
    environment: str = "ubuntu-latest sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ref: str = "refs/heads/develop",
    commit_sha: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    created_at: str = "2026-08-04T00:00:00Z",
    error: str = "",
    warning: str = "",
) -> dict:
    """Return one realistic GitHub analysis payload with overridable evidence."""
    return {
        "id": analysis_id,
        "tool": {"name": tool_name, "guid": tool_guid},
        "category": category,
        "analysis_key": analysis_key,
        "environment": environment,
        "ref": ref,
        "commit_sha": commit_sha,
        "created_at": created_at,
        "error": error,
        "warning": warning,
    }


def test_normalize_analysis_uses_nested_tool_and_stable_dimensions() -> None:
    """Volatile refs and commit SHAs must not split otherwise equal identities."""
    base = normalize_analysis(_analysis())
    pull = normalize_analysis(
        _analysis(
            analysis_id=2,
            analysis_key=(
                ".github/workflows/security.yml:scan refs/pull/862/merge"
            ),
            environment=(
                "ubuntu-latest sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ),
            ref="refs/pull/862/merge",
            commit_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
    )

    assert base.identity == pull.identity
    assert base.identity == AnalysisIdentity(
        tool_name="trivy",
        tool_guid="trivy-guid",
        category="filesystem",
        analysis_key=".github/workflows/security.yml:scan <ref>",
        environment="ubuntu-latest sha=<sha>",
    )


def test_normalize_analysis_preserves_matrix_dimensions() -> None:
    """Different matrix jobs must remain independent coverage identities."""
    linux = normalize_analysis(
        _analysis(environment="matrix.os=ubuntu-latest matrix.python=3.11")
    )
    windows = normalize_analysis(
        _analysis(environment="matrix.os=windows-latest matrix.python=3.11")
    )

    assert linux.identity != windows.identity


def test_normalize_analysis_defaults_optional_identity_fields() -> None:
    """Missing optional GUID and category values must normalize deterministically."""
    evidence = normalize_analysis(
        _analysis(tool_guid=None, category="", analysis_key="", environment="")
    )

    assert evidence.identity.tool_guid == ""
    assert evidence.identity.category == "default"
    assert evidence.identity.analysis_key == ""
    assert evidence.identity.environment == ""


def test_normalize_analysis_rejects_deprecated_top_level_tool_name() -> None:
    """The closing-down top-level tool_name field must not become a hidden dependency."""
    payload = _analysis()
    payload.pop("tool")
    payload["tool_name"] = "Trivy"

    with pytest.raises(ValueError, match=r"tool\.name"):
        normalize_analysis(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 0),
        ("id", "one"),
        ("ref", ""),
        ("commit_sha", "not-a-sha"),
        ("created_at", "not-a-timestamp"),
    ],
)
def test_normalize_analysis_rejects_malformed_required_evidence(
    field: str, value: object
) -> None:
    """Malformed analysis evidence must fail closed before comparison."""
    payload = _analysis()
    payload[field] = value

    with pytest.raises(ValueError):
        normalize_analysis(payload)


def test_build_snapshot_selects_latest_exact_analysis_per_identity() -> None:
    """Duplicate historical analyses must collapse to the latest exact-head result."""
    older = _analysis(
        analysis_id=1,
        created_at="2026-08-04T00:00:00Z",
        warning="old warning",
    )
    latest = _analysis(
        analysis_id=2,
        created_at="2026-08-04T01:00:00+00:00",
        warning="current warning",
    )

    snapshot = build_snapshot(
        [older, latest],
        scope="base",
        expected_refs=("refs/heads/develop",),
        expected_commit_shas=("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",),
    )

    assert snapshot.status == "ok"
    assert snapshot.complete is True
    assert len(snapshot.analyses) == 1
    assert snapshot.analyses[0].analysis_id == 2
    assert snapshot.analyses[0].warning == "current warning"


def test_build_snapshot_returns_unknown_for_malformed_or_inexact_evidence() -> None:
    """Malformed payloads and wrong-head analyses must not become false drift."""
    malformed = build_snapshot(
        [{"id": 1}],
        scope="current",
        expected_refs=("refs/pull/862/merge",),
        expected_commit_shas=("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",),
    )
    inexact = build_snapshot(
        [_analysis()],
        scope="current",
        expected_refs=("refs/pull/862/merge",),
        expected_commit_shas=("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",),
    )

    assert malformed.status == "unknown"
    assert malformed.reason == "malformed_analysis_payload"
    assert inexact.status == "unknown"
    assert inexact.reason == "no_exact_analysis_evidence"


def test_build_snapshot_preserves_complete_empty_current_evidence() -> None:
    """A completely paginated empty PR result is valid evidence of missing coverage."""
    snapshot = build_snapshot(
        [],
        scope="current",
        expected_refs=("refs/pull/862/merge",),
        expected_commit_shas=("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",),
    )

    assert snapshot.status == "ok"
    assert snapshot.complete is True
    assert snapshot.analyses == ()


def test_build_snapshot_returns_unknown_for_transport_state() -> None:
    """Permission, service, and pagination failures must remain explicit unknowns."""
    snapshot = build_snapshot(
        [],
        scope="current",
        expected_refs=("refs/pull/862/merge",),
        expected_commit_shas=(),
        complete=False,
        unknown_reason="permission_denied",
    )

    assert snapshot.status == "unknown"
    assert snapshot.complete is False
    assert snapshot.reason == "permission_denied"


def test_compare_snapshots_reports_clean_parity_and_warnings() -> None:
    """Comparable healthy analyses are clean while warnings remain auditable evidence."""
    base = build_snapshot(
        [_analysis()],
        scope="base",
        expected_refs=("refs/heads/develop",),
        expected_commit_shas=(),
    )
    current = build_snapshot(
        [
            _analysis(
                analysis_id=2,
                ref="refs/pull/862/merge",
                commit_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                analysis_key=(
                    ".github/workflows/security.yml:scan refs/pull/862/merge"
                ),
                environment=(
                    "ubuntu-latest sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                warning="rules_count unavailable for legacy SARIF",
            )
        ],
        scope="current",
        expected_refs=("refs/pull/862/merge",),
        expected_commit_shas=("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",),
    )

    assessment = compare_snapshots(base, current)

    assert assessment.status == "clean"
    assert assessment.missing == ()
    assert assessment.errored == ()
    assert assessment.warnings == (current.analyses[0],)


def test_compare_snapshots_reports_missing_and_errored_current_analysis() -> None:
    """Absent and failed current analyses must both block a clean comparison."""
    codeql = _analysis(
        analysis_id=10,
        tool_name="CodeQL",
        tool_guid="codeql-guid",
        category="/language:python",
        environment="ubuntu-latest",
    )
    trivy = _analysis()
    base = build_snapshot(
        [codeql, trivy],
        scope="base",
        expected_refs=("refs/heads/develop",),
        expected_commit_shas=(),
    )
    current = build_snapshot(
        [
            _analysis(
                analysis_id=20,
                ref="refs/pull/862/merge",
                commit_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                analysis_key=(
                    ".github/workflows/security.yml:scan refs/pull/862/merge"
                ),
                environment=(
                    "ubuntu-latest sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                error="SARIF upload failed",
            )
        ],
        scope="current",
        expected_refs=("refs/pull/862/merge",),
        expected_commit_shas=("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",),
    )

    assessment = compare_snapshots(base, current)

    assert assessment.status == "drift"
    assert tuple(item.tool_name for item in assessment.missing) == ("codeql",)
    assert assessment.errored == (current.analyses[0],)
    assert assessment.reason == "missing_or_unhealthy_current_analysis"


def test_compare_snapshots_returns_unknown_without_complete_healthy_base() -> None:
    """Unknown transport state or only errored base analyses cannot establish a baseline."""
    unknown_base = build_snapshot(
        [],
        scope="base",
        expected_refs=("refs/heads/develop",),
        expected_commit_shas=(),
        complete=False,
        unknown_reason="service_unavailable",
    )
    empty_current = build_snapshot(
        [],
        scope="current",
        expected_refs=("refs/pull/862/merge",),
        expected_commit_shas=(),
    )
    errored_base = build_snapshot(
        [_analysis(error="base scan failed")],
        scope="base",
        expected_refs=("refs/heads/develop",),
        expected_commit_shas=(),
    )

    assert compare_snapshots(unknown_base, empty_current).status == "unknown"
    assessment = compare_snapshots(errored_base, empty_current)
    assert assessment.status == "unknown"
    assert assessment.reason == "no_healthy_base_analysis"
