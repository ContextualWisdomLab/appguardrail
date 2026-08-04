"""Final statement-coverage tests for bounded collector control paths."""

from __future__ import annotations

from appguardrail_core.code_scanning import DriftAssessment
from scripts.ci import collect_code_scanning_drift as drift


class MultiRepositoryClient:
    """Client that exposes one pull in the first repository only."""

    def __init__(self) -> None:
        """Record every request while returning exact healthy comparison evidence."""
        self.calls: list[str] = []

    def pages(self, path, params=None):
        """Return one complete PR and its matching base/current analyses."""
        self.calls.append(path)
        if path.endswith("/pulls"):
            return drift.PageResult(
                "ok",
                (
                    {
                        "number": 1,
                        "html_url": "https://github.com/ContextualWisdomLab/one/pull/1",
                        "base": {"ref": "develop"},
                        "head": {"ref": "feature", "sha": "b" * 40},
                        "merge_commit_sha": "c" * 40,
                    },
                ),
                True,
            )
        analysis = {
            "id": 1,
            "tool": {"name": "Trivy", "guid": "trivy-guid"},
            "category": "filesystem",
            "analysis_key": "security:scan <ref>",
            "environment": "ubuntu",
            "ref": (
                "refs/heads/develop"
                if params and params.get("ref")
                else "refs/pull/1/merge"
            ),
            "commit_sha": "a" * 40 if params and params.get("ref") else "c" * 40,
            "created_at": "2026-08-04T00:00:00Z",
            "error": "",
            "warning": "",
        }
        return drift.PageResult("ok", (analysis,), True)


def test_collection_stops_before_querying_a_second_repository() -> None:
    """The global PR bound must break the outer repository loop deterministically."""
    client = MultiRepositoryClient()

    records = drift.collect_records(
        client,
        owner="ContextualWisdomLab",
        repositories=(
            "ContextualWisdomLab/one",
            "ContextualWisdomLab/two",
        ),
        max_pull_requests=1,
    )

    assert len(records) == 1
    assert all("/two/" not in path for path in client.calls)


class MalformedPullClient:
    """Client returning a non-object pull request payload."""

    def pages(self, path, params=None):
        """Return one malformed pull and reject unexpected analysis requests."""
        del params
        if path.endswith("/pulls"):
            return drift.PageResult("ok", (None,), True)
        raise AssertionError(path)


def test_collection_uses_zero_identity_for_non_object_pull() -> None:
    """Malformed non-object pull metadata must use the safe zero identity path."""
    records = drift.collect_records(
        MalformedPullClient(),
        owner="ContextualWisdomLab",
        repositories=("ContextualWisdomLab/demo",),
    )

    assert records[0].pr_number == 0
    assert records[0].assessment.reason == "malformed_pull_request"


class NoMutationClient:
    """Issue client that records calls for clean and unknown telemetry."""

    def __init__(self) -> None:
        """Initialize an empty mutation history."""
        self.calls: list[tuple] = []

    def pages(self, path, params=None):
        """Record unexpected inventory queries."""
        self.calls.append(("pages", path, params))
        return []

    def request(self, method, path, data=None):
        """Record unexpected writes."""
        self.calls.append((method, path, data))
        return data


def test_publish_returns_zero_before_issue_inventory_for_non_drift() -> None:
    """Clean and unknown records must return before any IssueOps API call."""
    template = drift.PullRequestDriftRecord(
        repository="ContextualWisdomLab/demo",
        pr_number=1,
        pr_url="",
        base_ref="refs/heads/develop",
        current_ref="refs/pull/1/merge",
        head_ref="refs/heads/feature",
        head_sha="b" * 40,
        merge_sha="c" * 40,
        assessment=DriftAssessment(status="clean"),
    )
    client = NoMutationClient()

    assert drift.publish_records(
        client,
        "ContextualWisdomLab/appguardrail",
        (template,),
    ) == 0
    assert client.calls == []
