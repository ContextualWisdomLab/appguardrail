"""Regression for GitHub repository identity case normalization."""

from datetime import datetime, timedelta, timezone

import pytest

from appguardrail_core.github_actions_evidence import (
    EvidenceValidationError,
    verify_actions_job,
)


RUN_ID = 30_769_144_488
JOB_ID = 91_553_355_284
HEAD_SHA = "2a83043b0239ba827153c934f87e469dba4f96f0"
CANONICAL_REPOSITORY = "ContextualWisdomLab/.github"
REQUESTED_REPOSITORY = "contextualwisdomlab/.github"
OBSERVED_AT = datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc)


def _source_payloads() -> tuple[dict[str, object], dict[str, object]]:
    """Return one exact authoritative run/job pair using GitHub canonical casing."""
    run: dict[str, object] = {
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
    job: dict[str, object] = {
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
    return run, job


def test_repository_identity_accepts_github_canonical_case_urls() -> None:
    """Treat requested identity as case-insensitive while binding exact IDs."""
    run, job = _source_payloads()

    evidence = verify_actions_job(
        REQUESTED_REPOSITORY,
        run,
        job,
        observed_at=OBSERVED_AT,
        max_age=timedelta(hours=48),
    )

    assert evidence.repository == CANONICAL_REPOSITORY
    assert evidence.run_id == RUN_ID
    assert evidence.job_id == JOB_ID
    assert evidence.detector_state == "failure"


def test_repository_case_variants_cannot_bypass_source_digest_deduplication() -> None:
    """Canonicalize equivalent requested casing before hashing source evidence."""
    run, job = _source_payloads()
    first = verify_actions_job(
        CANONICAL_REPOSITORY,
        run,
        job,
        observed_at=OBSERVED_AT,
        max_age=timedelta(hours=48),
    )

    with pytest.raises(EvidenceValidationError, match="duplicate source evidence digest"):
        verify_actions_job(
            REQUESTED_REPOSITORY,
            run,
            job,
            observed_at=OBSERVED_AT,
            max_age=timedelta(hours=48),
            seen_source_digests=[first.source_digest_sha256],
        )
