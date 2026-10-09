"""Fail-closed regressions for required GitHub Actions step evidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import appguardrail_core.github_actions_evidence as gae

REPOSITORY = "ContextualWisdomLab/appguardrail"
RUN_ID = 31879016068
JOB_ID = 95001996967
HEAD_SHA = "4d3747e931723f07160994a3f3f879eef8dc9fe0"
OBSERVED_AT = datetime(2026, 8, 15, 11, 0, tzinfo=timezone.utc)


def _run_payload() -> dict[str, object]:
    """Return a completed security workflow run fixture."""
    return {
        "id": RUN_ID,
        "name": "OpenCode Review",
        "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        "head_sha": HEAD_SHA,
        "head_branch": "feature/source-authoritative-actions-evidence-938",
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "updated_at": "2026-08-15T10:55:45Z",
        "pull_requests": [{"number": 939}],
    }


def _job_payload() -> dict[str, object]:
    """Return a completed security job fixture with one terminal step."""
    return {
        "id": JOB_ID,
        "run_id": RUN_ID,
        "name": "coverage-evidence",
        "workflow_name": "OpenCode Review",
        "html_url": (
            f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/job/{JOB_ID}"
        ),
        "status": "completed",
        "conclusion": "success",
        "completed_at": "2026-08-15T10:55:45Z",
        "steps": [
            {
                "number": 1,
                "name": "Verify coverage evidence",
                "status": "completed",
                "conclusion": "success",
            }
        ],
    }


@pytest.mark.parametrize("step_evidence", [None, []])
def test_verify_actions_job_rejects_missing_or_empty_steps(step_evidence):
    """Reject a terminal job whose authoritative step collection has no evidence."""
    job = _job_payload()
    if step_evidence is None:
        job.pop("steps")
    else:
        job["steps"] = step_evidence

    with pytest.raises(gae.EvidenceValidationError, match="steps"):
        gae.verify_actions_job(
            REPOSITORY,
            _run_payload(),
            job,
            observed_at=OBSERVED_AT,
            max_age=timedelta(hours=1),
        )
