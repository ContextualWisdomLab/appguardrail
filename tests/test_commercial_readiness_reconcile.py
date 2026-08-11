"""Regression tests for interrupted commercial-readiness issue selection."""

from __future__ import annotations

import json
from typing import Any

import pytest

from scripts.ci import commercial_readiness_loop as loop
from scripts.ci import commercial_readiness_reconcile as reconcile


class FakeClient:
    """Minimal GitHub client double for read-only recovery behavior."""

    def __init__(
        self,
        *,
        pulls: list[dict[str, Any]] | None = None,
        issues: list[dict[str, Any]] | None = None,
    ) -> None:
        """Store deterministic list responses and recorded mutation requests."""
        self.pulls = pulls or []
        self.issues = issues or []
        self.requests: list[tuple[str, str, dict[str, Any] | None]] = []

    def pages(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Return the configured payload for pull-request or issue endpoints."""
        del params
        if path.endswith("/pulls"):
            return self.pulls
        if path.endswith("/issues"):
            return self.issues
        raise AssertionError(f"unexpected list endpoint: {path}")

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Fail if the compatibility validator attempts any mutation."""
        del params
        self.requests.append((method, path, data))
        raise AssertionError(f"unexpected mutation: {method} {path}")


def _active_issue(*, number: int = 321) -> dict[str, Any]:
    """Build one active issue for the first reviewed commercial gap."""
    gap = loop.COMMERCIAL_GAPS[0]
    return {
        "number": number,
        "state": "open",
        "title": gap.title,
        "body": loop.gap_marker(gap.id),
        "labels": [loop.COMMERCIAL_LABEL],
    }


def test_reconcile_reports_active_issue_without_mutation() -> None:
    """An interrupted run resumes from the same validated issue identity."""
    client = FakeClient(issues=[_active_issue()])

    result = reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert result == loop.LoopResult(
        "wait-gap",
        loop.COMMERCIAL_GAPS[0].id,
        321,
    )
    assert client.requests == []


def test_reconcile_preserves_pr_first_policy() -> None:
    """No active issue is selected while any pull request remains open."""
    client = FakeClient(
        pulls=[{"number": 99}],
        issues=[_active_issue()],
    )

    result = reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert result == loop.LoopResult("wait-prs", None, None, (99,))
    assert client.requests == []


def test_reconcile_dry_run_matches_read_only_result() -> None:
    """Dry-run and normal validation are identical because no mutation exists."""
    client = FakeClient(issues=[_active_issue()])

    result = reconcile.reconcile_handoff(
        client,
        "ContextualWisdomLab/appguardrail",
        dry_run=True,
    )

    assert result.action == "wait-gap"
    assert result.issue_number == 321
    assert client.requests == []


def test_reconcile_rejects_active_issue_without_positive_number() -> None:
    """Malformed active issue payloads cannot become agent targets."""
    client = FakeClient(issues=[_active_issue(number=0)])

    with pytest.raises(RuntimeError, match="positive issue number"):
        reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")


def test_reconcile_rejects_mismatched_registry_identity() -> None:
    """Read-only recovery keeps the same title-and-marker trust boundary."""
    issue = _active_issue()
    issue["title"] = "untrusted replacement"
    client = FakeClient(issues=[issue])

    with pytest.raises(RuntimeError, match="title does not match reviewed registry"):
        reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert client.requests == []


def test_reconcile_returns_noop_without_active_gap() -> None:
    """A repository without an active reviewed gap requires no recovery."""
    client = FakeClient()

    result = reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert result == loop.LoopResult("noop", None, None)
    assert client.requests == []


def test_parse_args_supports_explicit_and_environment_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI parsing preserves explicit dry-run and repository defaults."""
    explicit = reconcile.parse_args(
        ["--repository", "ContextualWisdomLab/appguardrail", "--dry-run"]
    )
    assert explicit.repository == "ContextualWisdomLab/appguardrail"
    assert explicit.dry_run is True

    monkeypatch.setenv("GITHUB_REPOSITORY", "ContextualWisdomLab/appguardrail")
    defaulted = reconcile.parse_args([])
    assert defaulted.repository == "ContextualWisdomLab/appguardrail"
    assert defaulted.dry_run is False


def test_main_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """The compatibility CLI fails closed before GitHub access without a token."""
    monkeypatch.delenv("GH_TOKEN", raising=False)

    with pytest.raises(SystemExit, match="GH_TOKEN is required"):
        reconcile.main(["--repository", "ContextualWisdomLab/appguardrail"])


def test_main_prints_machine_readable_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The compatibility CLI emits a deterministic JSON decision contract."""
    client = FakeClient()
    monkeypatch.setenv("GH_TOKEN", "workflow-token")
    monkeypatch.setattr(loop, "GitHub", lambda token: client)

    assert reconcile.main(["--repository", "ContextualWisdomLab/appguardrail"]) == 0

    assert json.loads(capsys.readouterr().out) == {
        "action": "noop",
        "gap_id": None,
        "issue_number": None,
        "pull_requests": [],
    }
