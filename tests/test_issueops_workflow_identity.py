"""Regression tests for stable organization security workflow identities."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from appguardrail_core import issueops


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "ci"
    / "collect_org_security_failures.py"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_org_security_failures_workflow_identity", MODULE_PATH
)
collector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = collector
assert SPEC.loader is not None
SPEC.loader.exec_module(collector)

_DYNAMIC_WORKFLOW = (
    "Required OpenCode Review "
    "ContextualWisdomLab/EgressWeave#1@"
    "2d9dc094409bdc3574bcee6b9a5c52ea920b3936"
)
_CANONICAL_TITLE = (
    "[security-failure] ContextualWisdomLab/EgressWeave: Required OpenCode Review"
)


class _IssueClient:
    """Return a controlled issue list to the collector indexer."""

    def __init__(self, issues: list[dict]):
        """Store the issues that ``pages`` should return."""
        self.issues = issues

    def pages(self, _path: str, _params: dict | None = None) -> list[dict]:
        """Return the configured issue list."""
        return self.issues


def _finding(workflow: str = _DYNAMIC_WORKFLOW) -> dict[str, str]:
    """Build the minimal finding fields consumed by the title helper."""
    return {
        "repo": "ContextualWisdomLab/EgressWeave",
        "workflow": workflow,
    }


def test_security_failure_title_strips_dynamic_pr_sha_suffix() -> None:
    """Per-head dispatch names must collapse into one durable issue identity."""
    assert issueops.title(_finding()) == _CANONICAL_TITLE


def test_security_failure_marker_stores_canonical_workflow_identity() -> None:
    """Hidden deduplication state must not retain the changing dispatch suffix."""
    body = issueops.marker(
        "ContextualWisdomLab/EgressWeave",
        _DYNAMIC_WORKFLOW,
        {"1:2"},
    )

    assert issueops.parse_marker(body)["workflow"] == "Required OpenCode Review"


def test_issue_index_reuses_legacy_dynamic_issue_under_canonical_key() -> None:
    """Existing per-head issues must be reused instead of creating another issue."""
    issue = {
        "number": 851,
        "state": "open",
        "title": (
            "[security-failure] ContextualWisdomLab/EgressWeave: "
            + _DYNAMIC_WORKFLOW
        ),
        "body": issueops.marker(
            "ContextualWisdomLab/EgressWeave",
            _DYNAMIC_WORKFLOW,
            {"1:2"},
        ),
    }

    indexed = collector.issue_index(
        _IssueClient([issue]),
        "ContextualWisdomLab/appguardrail",
    )

    assert indexed == {_CANONICAL_TITLE: issue}


def test_short_sha_like_suffix_is_not_rewritten() -> None:
    """Only the exact generated full-SHA suffix may be normalized."""
    workflow = "Review ContextualWisdomLab/EgressWeave#1@deadbeef"

    assert issueops.title(_finding(workflow)) == (
        "[security-failure] ContextualWisdomLab/EgressWeave: " + workflow
    )
