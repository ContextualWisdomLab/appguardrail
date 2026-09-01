"""Regression for GitHub repository identity case normalization."""

from datetime import datetime, timedelta, timezone

from appguardrail_core.github_actions_evidence import verify_actions_job


RUN_ID = 30_769_144_488
JOB_ID = 91_553_355_284
HEAD_SHA = "2a83043b0239ba827153c934f87e469dba4f96f0"
CANONICAL_REPOSITORY = "ContextualWisdomLab/.github"
REQUESTED_REPOSITORY = "contextualwisdomlab/.github"
OBSERVED_AT = datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc)


def test_repository_identity_accepts_github_canonical_case_urls() -> None:
    """Treat repository identity as case-insensitive while binding exact IDs."""
    run = {
        "id": RUN_ID,
        "name": "OpenCode Review Dispatch",
        "html_url": f"https://github.com/{CANONICAL_REPOSITORY}/actions/runs/{RUN_ID}",
        "head_sha": HEAD_SHA,
        "head_branch": "main",
        "event": "repository_dispatch",
        "status": "completed",
        "conclusion": "failure",
        "updated_at": "2026-08-02T23:44:00Z",
        "pull_requests": [],
    }
    job = {
        "id": JOB_ID,
        "run_id": RUN_ID,
        "name": "opencode-review",
        "workflow_name": "OpenCode Review Dispatch",
        "html_url": (
            f"https://github.com/{CANONICAL_REPOSITORY}/actions/runs/{RUN_ID}/job/{JOB_ID}"
        ),
        "status": "completed",
        "conclusion": "failure",
        "completed_at": "2026-08-02T23:43:30Z",
        "steps": [
            {
                "number": 19,
                "name": "Publish review",
                "status": "completed",
                "conclusion": "failure",
            }
        ],
    }

    evidence = verify_actions_job(
        REQUESTED_REPOSITORY,
        run,
        job,
        observed_at=OBSERVED_AT,
        max_age=timedelta(hours=48),
    )

    assert evidence.run_id == RUN_ID
    assert evidence.job_id == JOB_ID
    assert evidence.detector_state == "failure"
