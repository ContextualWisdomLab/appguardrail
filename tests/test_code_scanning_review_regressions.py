"""Regression tests for review-identified Code Scanning drift edge cases."""

from __future__ import annotations

from pathlib import Path

import pytest

from appguardrail_core.code_scanning import AnalysisIdentity, DriftAssessment
from scripts.ci import collect_code_scanning_drift as drift
from scripts.ci.verify_module_coverage import CoverageTarget, verify_coverage


def _identity(tool_name: str) -> AnalysisIdentity:
    """Return one identity containing caller-controlled SARIF text."""
    return AnalysisIdentity(
        tool_name=tool_name,
        tool_guid="tool-guid",
        category="filesystem",
        analysis_key="security:scan <ref>",
        environment="ubuntu",
    )


def _record(
    identities: tuple[AnalysisIdentity, ...],
) -> drift.PullRequestDriftRecord:
    """Return one exact-head confirmed-drift record."""
    return drift.PullRequestDriftRecord(
        repository="ContextualWisdomLab/demo",
        pr_number=42,
        pr_url="https://github.com/ContextualWisdomLab/demo/pull/42",
        base_ref="refs/heads/develop",
        current_ref="refs/pull/42/merge",
        head_ref="refs/heads/feature",
        head_sha="b" * 40,
        merge_sha="c" * 40,
        assessment=DriftAssessment(
            status="drift",
            missing=identities,
            reason="missing_or_unhealthy_current_analysis",
        ),
    )


def test_marker_round_trip_survives_html_comment_terminator_in_identity() -> None:
    """Untrusted SARIF identity text must not truncate the hidden JSON marker."""
    record = _record((_identity("unsafe-->tool"),))

    marker = drift.drift_marker(record)
    parsed = drift.parse_drift_marker(marker)

    assert marker.count(drift.MARKER_SUFFIX) == 1
    assert parsed["head_sha"] == record.head_sha
    assert "unsafe-->tool" in parsed["identities"][0]


class IssueClient:
    """Issue client exposing malformed inventory and bodyless create responses."""

    def __init__(self, issues=()) -> None:
        """Store issue inventory and record every mutation."""
        self.issues = list(issues)
        self.calls: list[tuple] = []

    def pages(self, path, params=None):
        """Return configured issue inventory."""
        self.calls.append(("pages", path, params))
        return list(self.issues)

    def request(self, method, path, data=None):
        """Record writes and simulate a bodyless successful create response."""
        self.calls.append((method, path, data))
        if method == "POST" and path.endswith("/issues"):
            return None
        return data


def test_issue_index_ignores_title_only_entries_without_positive_number() -> None:
    """Malformed issue records must not become PATCH targets or crash publication."""
    malformed = {
        "state": "open",
        "title": drift.drift_issue_title(_record((_identity("trivy"),))),
        "body": "malformed",
    }
    client = IssueClient((malformed,))

    assert drift._issue_items(client, "ContextualWisdomLab/appguardrail") == []


def test_bodyless_create_response_is_not_cached_as_issue_zero() -> None:
    """A bodyless create response must never lead to a later `/issues/0` PATCH."""
    first = _record((_identity("trivy"),))
    changed = _record((_identity("trivy"), _identity("codeql")))
    client = IssueClient()

    assert drift.publish_records(
        client,
        "ContextualWisdomLab/appguardrail",
        (first, changed),
    ) == 2
    assert not any("/issues/0" in str(call) for call in client.calls)
    assert sum(
        call[0] == "POST" and call[1].endswith("/issues")
        for call in client.calls
    ) == 2


def test_coverage_gate_rejects_target_without_executable_statements() -> None:
    """An empty or unmeasurable module cannot report successful `0/0` coverage."""
    target = CoverageTarget(
        path=Path("empty_module.py"),
        executable=frozenset(),
        executed=frozenset(),
    )

    with pytest.raises(RuntimeError, match="no executable statement lines"):
        verify_coverage((target,))
