"""Validation edges for source-authoritative GitHub Actions evidence."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import appguardrail_core.github_actions_evidence as evidence_module

OBSERVED_AT = datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc)
REPOSITORY = "ContextualWisdomLab/.github"
RUN_ID = 30_769_144_488
JOB_ID = 91_553_355_284
HEAD_SHA = "2a83043b0239ba827153c934f87e469dba4f96f0"


def run_payload(**overrides):
    """Return a bounded security workflow run fixture."""
    payload = {
        "id": RUN_ID,
        "name": "OpenCode Review Dispatch current-head",
        "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        "head_sha": HEAD_SHA,
        "head_branch": "main",
        "event": "repository_dispatch",
        "status": "completed",
        "conclusion": "failure",
        "updated_at": "2026-08-02T23:44:00Z",
        "pull_requests": [],
    }
    payload.update(overrides)
    return payload


def job_payload(**overrides):
    """Return a bounded security workflow job fixture."""
    payload = {
        "id": JOB_ID,
        "run_id": RUN_ID,
        "name": "opencode-review",
        "workflow_name": "OpenCode Review Dispatch",
        "html_url": (
            f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/job/{JOB_ID}"
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
    payload.update(overrides)
    return payload


def test_rejects_non_timedelta_age_and_unfinished_step():
    """Reject ambiguous freshness units and non-terminal step evidence."""
    with pytest.raises(
        evidence_module.EvidenceValidationError, match="positive timedelta"
    ):
        evidence_module.verify_actions_job(
            REPOSITORY,
            run_payload(),
            job_payload(),
            observed_at=OBSERVED_AT,
            max_age=1,
        )

    with pytest.raises(
        evidence_module.EvidenceValidationError, match="step status"
    ):
        evidence_module.verify_actions_job(
            REPOSITORY,
            run_payload(),
            job_payload(
                steps=[
                    {
                        "number": 1,
                        "name": "Still running",
                        "status": "in_progress",
                        "conclusion": None,
                    }
                ]
            ),
            observed_at=OBSERVED_AT,
            max_age=timedelta(hours=48),
        )


def test_identifier_rejects_float_and_non_ascii_digits():
    """Prevent lossy integer coercion and Unicode digit ambiguity."""
    for value in (1.0, "\uff12"):  # FULLWIDTH DIGIT TWO
        with pytest.raises(
            evidence_module.EvidenceValidationError, match="positive integer"
        ):
            evidence_module._positive_identifier(value, "id")


def test_client_rejects_crlf_in_bearer_token_before_header_construction():
    """Reject HTTP field-line injection material at the credential boundary."""
    for token in (
        "valid-prefix\rX-Injected: yes",
        "valid-prefix\nX-Injected: yes",
        "valid-prefix\x00suffix",
    ):
        with pytest.raises(ValueError, match="control characters"):
            evidence_module.GitHubApiClient(token)


def test_cli_rejects_non_finite_or_excessive_age_before_auth(monkeypatch, capsys):
    """Fail closed on invalid freshness windows without requiring a credential."""
    monkeypatch.delenv("APPGUARDRAIL_GITHUB_TOKEN", raising=False)
    base = [
        "--repository",
        REPOSITORY,
        "--run-id",
        str(RUN_ID),
        "--job-id",
        str(JOB_ID),
    ]
    for value in (
        "nan",
        "inf",
        "0",
        str(evidence_module.MAX_AGE_HOURS + 1),
    ):
        assert evidence_module.main(
            [*base, "--max-age-hours", value]
        ) == 2
        assert json.loads(capsys.readouterr().err)["error_code"] == "invalid_max_age"
