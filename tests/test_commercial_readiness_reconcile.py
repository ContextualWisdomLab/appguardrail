"""Regression tests for interrupted commercial-readiness issue handoffs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

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


def _active_issue(*, labels: list[Any]) -> dict[str, Any]:
    """Build one active issue for the first reviewed commercial gap."""
    gap = loop.COMMERCIAL_GAPS[0]
    return {
        "number": 321,
        "state": "open",
        "body": loop.gap_marker(gap.id),
        "labels": labels,
    }


def test_reconcile_repairs_missing_jules_label() -> None:
    """A partial create-then-label failure is repaired on the next pass."""
    client = FakeClient(issues=[_active_issue(labels=[loop.COMMERCIAL_LABEL])])

    result = reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert result == loop.LoopResult(
        "repair-gap",
        loop.COMMERCIAL_GAPS[0].id,
        321,
    )
    assert client.requests[-1] == (
        "POST",
        "/repos/ContextualWisdomLab/appguardrail/issues/321/labels",
        {"labels": [loop.JULES_LABEL]},
    )


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


def test_reconcile_returns_noop_without_active_gap() -> None:
    """A repository without an active reviewed gap requires no recovery."""
    client = FakeClient()

    result = reconcile.reconcile_handoff(client, "ContextualWisdomLab/appguardrail")

    assert result == loop.LoopResult("noop", None, None)


def test_workflow_runs_recovery_even_after_primary_step_failure() -> None:
    """The reviewed workflow retains a fail-closed always-run recovery step."""
    workflow = Path(".github/workflows/commercial-readiness-loop.yml").read_text(
        encoding="utf-8"
    )

    assert "if: always()" in workflow
    assert "scripts.ci.commercial_readiness_reconcile" in workflow
