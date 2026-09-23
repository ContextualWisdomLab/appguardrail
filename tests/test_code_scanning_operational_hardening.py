"""Operational hardening contracts for the scheduled Code Scanning collector."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci import collect_code_scanning_drift as drift

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "org-security-failure-collector.yml"


class StatusClient:
    """Client that raises one typed GitHub API response during label creation."""

    def __init__(self, status: int) -> None:
        """Store the response status for deterministic error handling."""
        self.status = status

    def request(self, *_args, **_kwargs):
        """Raise the configured typed GitHub API error."""
        raise drift.GitHubAPIError(self.status)


def test_label_creation_uses_typed_422_status_only() -> None:
    """Only GitHub's explicit already-exists status may be ignored."""
    drift._ensure_label(
        StatusClient(422),
        "ContextualWisdomLab/appguardrail",
        drift.DRIFT_LABEL,
    )
    with pytest.raises(drift.GitHubAPIError) as exc_info:
        drift._ensure_label(
            StatusClient(500),
            "ContextualWisdomLab/appguardrail",
            drift.DRIFT_LABEL,
        )
    assert exc_info.value.status == 500


@pytest.mark.parametrize("raw", ["not-a-number", "0", "-1"])
def test_invalid_environment_pull_request_bound_uses_argparse_error(
    monkeypatch: pytest.MonkeyPatch,
    raw: str,
) -> None:
    """Invalid scheduled limits must fail with SystemExit instead of a traceback."""
    monkeypatch.setenv("CODE_SCANNING_DRIFT_MAX_PULL_REQUESTS", raw)

    with pytest.raises(SystemExit):
        drift.parse_args([])


def test_workflow_sets_an_explicit_bounded_pull_request_limit() -> None:
    """The 30-minute organization job must not rely on an implicit request bound."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    drift_step = workflow.split(
        "      - name: Collect Code Scanning analysis drift\n",
        1,
    )[1]

    assert '--max-pull-requests "50"' in drift_step
