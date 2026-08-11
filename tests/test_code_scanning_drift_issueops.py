"""IssueOps contract tests for confirmed live Code Scanning analysis drift."""

from __future__ import annotations

from appguardrail_core.code_scanning import (
    AnalysisEvidence,
    AnalysisIdentity,
    DriftAssessment,
)
from scripts.ci.collect_code_scanning_drift import (
    DRIFT_LABEL,
    MARKER_PREFIX,
    MAX_ISSUE_BODY_CHARS,
    PullRequestDriftRecord,
    drift_issue_title,
    drift_marker,
    parse_drift_marker,
    publish_records,
    render_drift_issue,
)


def _identity(
    tool_name: str = "trivy", category: str = "filesystem"
) -> AnalysisIdentity:
    """Return one stable analysis identity for publication tests."""
    return AnalysisIdentity(
        tool_name=tool_name,
        tool_guid=f"{tool_name}-guid",
        category=category,
        analysis_key=".github/workflows/security.yml:scan <ref>",
        environment="ubuntu-latest",
    )


def _errored(identity: AnalysisIdentity | None = None) -> AnalysisEvidence:
    """Return one exact current analysis with a GitHub execution error."""
    return AnalysisEvidence(
        identity=identity or _identity(),
        analysis_id=22,
        ref="refs/pull/42/merge",
        commit_sha="cccccccccccccccccccccccccccccccccccccccc",
        created_at="2026-08-04T00:00:00Z",
        error="SARIF upload failed",
        warning="partial rule metadata",
    )


def _record(
    *,
    head_sha: str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    missing: tuple[AnalysisIdentity, ...] | None = None,
    errored: tuple[AnalysisEvidence, ...] = (),
    status: str = "drift",
    reason: str = "missing_or_unhealthy_current_analysis",
) -> PullRequestDriftRecord:
    """Return one bounded PR record with configurable assessment evidence."""
    assessment = DriftAssessment(
        status=status,
        missing=(_identity(),) if missing is None and status == "drift" else (missing or ()),
        errored=errored,
        reason=reason,
    )
    return PullRequestDriftRecord(
        repository="ContextualWisdomLab/demo",
        pr_number=42,
        pr_url="https://github.com/ContextualWisdomLab/demo/pull/42",
        base_ref="refs/heads/develop",
        current_ref="refs/pull/42/merge",
        head_ref="refs/heads/feature/live-drift",
        head_sha=head_sha,
        merge_sha="cccccccccccccccccccccccccccccccccccccccc",
        assessment=assessment,
    )


def test_marker_round_trip_sorts_normalized_identity_evidence() -> None:
    """The hidden marker must be deterministic for the exact head and drift set."""
    record = _record(
        missing=(
            _identity("trivy", "filesystem"),
            _identity("codeql", "/language:python"),
        ),
        errored=(_errored(_identity("semgrep", "semgrep")),),
    )

    marker = drift_marker(record)
    parsed = parse_drift_marker(marker)

    assert marker.startswith(MARKER_PREFIX)
    assert parsed["repo"] == "ContextualWisdomLab/demo"
    assert parsed["pr"] == 42
    assert parsed["head_sha"] == record.head_sha
    assert parsed["evidence_key"]
    assert parsed["identities"] == sorted(parsed["identities"])
    assert parse_drift_marker("ordinary issue") == {}
    assert parse_drift_marker(f"{MARKER_PREFIX} malformed -->") == {}


def test_issue_title_is_stable_per_exact_pull_request_head() -> None:
    """Different heads must never be collapsed into one live-state issue."""
    first = drift_issue_title(_record())
    second = drift_issue_title(_record(head_sha="dddddddddddddddddddddddddddddddddddddddd"))

    assert first == "[code-scanning-drift] ContextualWisdomLab/demo#42@bbbbbbbbbbbb"
    assert first != second


def test_rendered_issue_separates_live_state_from_source_heuristic() -> None:
    """Buyer evidence must state its API source and preserve errors and refs."""
    record = _record(
        missing=(_identity("codeql", "/language:python"),),
        errored=(_errored(),),
    )

    body = render_drift_issue(record)

    assert len(body) <= MAX_ISSUE_BODY_CHARS
    assert drift_marker(record) in body
    assert "live GitHub Code Scanning analysis state" in body
    assert "not inferred from repository workflow text" in body
    assert "refs/heads/develop" in body
    assert "refs/pull/42/merge" in body
    assert record.head_sha in body
    assert record.merge_sha in body
    assert "codeql" in body
    assert "SARIF upload failed" in body
    assert "github-actions-sarif-missing-pull-request-trigger" in body


class FakeClient:
    """Small issue client double for deterministic publish behavior."""

    def __init__(self, issues=None):
        """Store existing issues and record every mutation."""
        self.issues = list(issues or [])
        self.calls: list[tuple] = []
        self.next_number = 900

    def pages(self, path, params=None):
        """Return all configured issues for the dedicated label query."""
        self.calls.append(("pages", path, params))
        return list(self.issues)

    def request(self, method, path, data=None):
        """Record labels, issue creates, issue updates, and comments."""
        self.calls.append(("request", method, path, data))
        if method == "POST" and path.endswith("/labels") and "/issues/" not in path:
            return data
        if method == "POST" and path.endswith("/issues"):
            issue = {
                "number": self.next_number,
                "state": "open",
                "title": data["title"],
                "body": data["body"],
                "labels": data["labels"],
            }
            self.next_number += 1
            self.issues.append(issue)
            return issue
        if method == "PATCH" and "/issues/" in path:
            number = int(path.rsplit("/", 1)[1])
            issue = next(item for item in self.issues if item["number"] == number)
            issue.update(data)
            return issue
        if method == "POST" and path.endswith("/comments"):
            return {"id": 1}
        raise AssertionError(f"unexpected request: {method} {path}")


def _existing(record: PullRequestDriftRecord, *, state: str = "open") -> dict:
    """Return one existing marker-bearing issue for an exact PR head."""
    return {
        "number": 321,
        "state": state,
        "title": drift_issue_title(record),
        "body": render_drift_issue(record),
        "labels": [DRIFT_LABEL],
    }


def test_publish_creates_one_bounded_issue_for_confirmed_drift_only() -> None:
    """Clean and unknown records must remain in telemetry without issue mutation."""
    drift = _record()
    client = FakeClient()

    published = publish_records(
        client,
        "ContextualWisdomLab/appguardrail",
        (
            _record(status="clean", reason=""),
            _record(status="unknown", reason="permission_denied"),
            drift,
        ),
    )

    assert published == 1
    created = next(
        call
        for call in client.calls
        if call[:3]
        == (
            "request",
            "POST",
            "/repos/ContextualWisdomLab/appguardrail/issues",
        )
    )
    assert created[3]["title"] == drift_issue_title(drift)
    assert DRIFT_LABEL in created[3]["labels"]
    assert len(created[3]["body"]) <= MAX_ISSUE_BODY_CHARS


def test_publish_skips_repeat_evidence_for_the_same_exact_head() -> None:
    """Scheduled repetitions must not create comments or body churn."""
    record = _record()
    client = FakeClient([_existing(record)])

    assert publish_records(
        client,
        "ContextualWisdomLab/appguardrail",
        (record,),
    ) == 0
    assert not [call for call in client.calls if call[:2] == ("request", "PATCH")]
    assert not [call for call in client.calls if str(call[2]).endswith("/comments")]


def test_publish_updates_changed_evidence_but_reuses_the_exact_head_issue() -> None:
    """A changed missing set on one head must update, not duplicate, its issue."""
    original = _record()
    changed = _record(
        missing=(
            _identity("trivy", "filesystem"),
            _identity("codeql", "/language:python"),
        )
    )
    client = FakeClient([_existing(original)])

    assert publish_records(
        client,
        "ContextualWisdomLab/appguardrail",
        (changed,),
    ) == 1
    patches = [call for call in client.calls if call[:2] == ("request", "PATCH")]
    comments = [call for call in client.calls if str(call[2]).endswith("/comments")]
    assert len(patches) == 1
    assert len(comments) == 1
    assert parse_drift_marker(patches[0][3]["body"])["evidence_key"] == (
        parse_drift_marker(drift_marker(changed))["evidence_key"]
    )


def test_publish_reopens_only_the_matching_exact_head_issue() -> None:
    """A closed matching issue is reusable, but a new head requires a new issue."""
    old = _record()
    new = _record(head_sha="dddddddddddddddddddddddddddddddddddddddd")
    client = FakeClient([_existing(old, state="closed")])

    assert publish_records(
        client,
        "ContextualWisdomLab/appguardrail",
        (old, new),
    ) == 1
    assert any(
        call[:2] == ("request", "POST")
        and call[2] == "/repos/ContextualWisdomLab/appguardrail/issues"
        for call in client.calls
    )
    assert not [
        call
        for call in client.calls
        if call[:2] == ("request", "PATCH") and call[3].get("state") == "open"
    ]


def test_rendered_issue_fails_closed_when_evidence_exceeds_body_limit() -> None:
    """Oversized evidence must be rejected rather than silently truncated ambiguously."""
    record = _record(
        errored=(
            AnalysisEvidence(
                identity=_identity(),
                analysis_id=22,
                ref="refs/pull/42/merge",
                commit_sha="cccccccccccccccccccccccccccccccccccccccc",
                created_at="2026-08-04T00:00:00Z",
                error="x" * MAX_ISSUE_BODY_CHARS,
                warning="",
            ),
        )
    )

    try:
        render_drift_issue(record)
    except ValueError as exc:
        assert "bounded" in str(exc)
    else:
        raise AssertionError("oversized drift evidence must fail closed")
