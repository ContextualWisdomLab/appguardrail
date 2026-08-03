"""Regression tests for interrupted commercial-readiness issue handoffs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import commercial_readiness_loop as loop
from scripts.ci import commercial_readiness_reconcile as reconcile


class FakeClient:
    """Minimal GitHub client double for recovery behavior."""

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
        """Record one mutation request and return an empty JSON object."""
        del params
        self.requests.append((method, path, data))
        return {}


def _active_issue(*, labels: list[Any], number: int = 321) -> dict[str, Any]:
    """Build one active issue for the first reviewed commercial gap."""
    gap = loop.COMMERCIAL_GAPS[0]
    return {
        "number": number,
        "state": "open",
        "body": loop.gap_marker(gap.id),
        "labels": labels,
    }


def test_label_names_accepts_supported_shapes_and_ignores_noise() -> None:
    """Only nonempty string labels from supported GitHub shapes are retained."""
    assert reconcile._label_names(
        {
            "labels": [
                "",
                loop.COMMERCIAL_LABEL,
                7,
                {},
                {"name": 9},
                {"name": loop.JULES_LABEL},
            ]
        }
    ) == frozenset({loop.COMMERCIAL_LABEL, loop.JULES_LABEL})
    assert reconcile._label_names({"labels": None}) == frozenset()


def test_reconcile_repairs_missing_jules_label() -> None:
    """A partial create-then-label failure is repaired on the next pass."""
    client = FakeClient(issues=[_active_issue(labels=[loop.COMMERCIAL_LABEL])])

    result = reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert result == loop.LoopResult(
        "repair-gap",
        loop.COMMERCIAL_GAPS[0].id,
        321,
    )
    assert client.requests == [
        (
            "POST",
            "/repos/ContextualWisdomLab/appguardrail/labels",
            {
                "name": loop.JULES_LABEL,
                "color": "1D76DB",
                "description": "Dispatch this reviewed issue to the Jules coding agent.",
            },
        ),
        (
            "POST",
            "/repos/ContextualWisdomLab/appguardrail/issues/321/labels",
            {"labels": [loop.JULES_LABEL]},
        ),
    ]


def test_reconcile_accepts_github_label_objects_without_mutation() -> None:
    """Normal GitHub label objects are recognized as an intact handoff."""
    client = FakeClient(
        issues=[_active_issue(labels=[{"name": loop.JULES_LABEL}])]
    )

    result = reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert result.action == "wait-gap"
    assert client.requests == []


def test_reconcile_preserves_pr_first_policy() -> None:
    """No issue handoff is repaired while any pull request remains open."""
    client = FakeClient(
        pulls=[{"number": 99}],
        issues=[_active_issue(labels=[])],
    )

    result = reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert result == loop.LoopResult("wait-prs", None, None, (99,))
    assert client.requests == []


def test_reconcile_dry_run_reports_without_mutation() -> None:
    """Dry-run mode exposes the pending repair without changing GitHub state."""
    client = FakeClient(issues=[_active_issue(labels=[])])

    result = reconcile.reconcile_handoff(
        client,
        "ContextualWisdomLab/appguardrail",
        dry_run=True,
    )

    assert result.action == "repair-gap"
    assert client.requests == []


def test_reconcile_rejects_active_issue_without_positive_number() -> None:
    """Malformed active issue payloads cannot be used as mutation targets."""
    client = FakeClient(issues=[_active_issue(labels=[], number=0)])

    with pytest.raises(RuntimeError, match="positive issue number"):
        reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")


def test_reconcile_returns_noop_without_active_gap() -> None:
    """A repository without an active reviewed gap requires no recovery."""
    client = FakeClient()

    result = reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert result == loop.LoopResult("noop", None, None)


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
    """The recovery CLI fails closed before GitHub access without a token."""
    monkeypatch.delenv("GH_TOKEN", raising=False)

    with pytest.raises(SystemExit, match="GH_TOKEN is required"):
        reconcile.main(["--repository", "ContextualWisdomLab/appguardrail"])


def test_main_prints_machine_readable_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The recovery CLI emits a deterministic JSON decision contract."""
    client = FakeClient()
    monkeypatch.setenv("GH_TOKEN", "workflow-token")
    monkeypatch.setattr(loop, "GitHub", lambda token: client)

    assert reconcile.main(
        ["--repository", "ContextualWisdomLab/appguardrail"]
    ) == 0

    assert json.loads(capsys.readouterr().out) == {
        "action": "noop",
        "gap_id": None,
        "issue_number": None,
        "pull_requests": [],
    }


def test_workflow_runs_recovery_even_after_primary_step_failure() -> None:
    """The reviewed workflow retains a fail-closed always-run recovery step."""
    workflow = Path(".github/workflows/commercial-readiness-loop.yml").read_text(
        encoding="utf-8"
    )

    assert "if: always()" in workflow
    assert "scripts.ci.commercial_readiness_reconcile" in workflow
