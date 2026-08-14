"""Defensive branch coverage for GitHub Actions source evidence."""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest

import appguardrail_core.github_actions_evidence as gae

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


def verify(*, run=None, job=None, **kwargs):
    """Verify one fixture with deterministic time bounds."""
    return gae.verify_actions_job(
        REPOSITORY,
        run_payload() if run is None else run,
        job_payload() if job is None else job,
        observed_at=OBSERVED_AT,
        max_age=timedelta(hours=48),
        **kwargs,
    )


class FakeResponse:
    """In-memory response implementing the production client's HTTP subset."""

    def __init__(self, payload, content_type="application/json", status=200):
        """Encode a JSON-like payload or preserve supplied bytes."""
        self.body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.headers = {"content-type": content_type}
        self.status = status

    def read(self, amount=-1):
        """Return at most the requested bytes."""
        return self.body if amount < 0 else self.body[:amount]

    def __enter__(self):
        """Enter the response context."""
        return self

    def __exit__(self, exc_type, exc, traceback):
        """Exit without suppressing errors."""
        return False


class FakeOpener:
    """Record requests and return or raise deterministic queued results."""

    def __init__(self, *results):
        """Store results for subsequent requests."""
        self.results = list(results)
        self.requests = []

    def open(self, request, timeout):
        """Return or raise the next result."""
        self.requests.append((request, timeout))
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def test_redirect_and_client_constructor_edges():
    """Reject redirects and invalid transport limits before acquisition."""
    assert (
        gae._NoRedirect().redirect_request(
            None, None, 302, "redirect", {}, "https://evil.example"
        )
        is None
    )
    for token in (None, " "):
        with pytest.raises(ValueError, match="token"):
            gae.GitHubApiClient(token)
    with pytest.raises(ValueError, match="API root"):
        gae.GitHubApiClient("token", api_root="https://example.com")
    with pytest.raises(ValueError, match="timeout"):
        gae.GitHubApiClient("token", timeout_seconds=0)
    with pytest.raises(ValueError, match="max_response"):
        gae.GitHubApiClient("token", max_response_bytes=0)
    assert gae.GitHubApiClient(
        "token", api_root="https://api.github.com/"
    )._opener


def test_get_json_transport_edges():
    """Cover path, status, network, encoding, and content-type failures."""
    client = gae.GitHubApiClient("token", opener=FakeOpener(FakeResponse({})))
    for path in (
        None,
        "https://evil.example/api",
        "/repos/a/b/actions/runs/0",
    ):
        with pytest.raises(ValueError, match="path"):
            client.get_json(path)

    with pytest.raises(gae.EvidenceAcquisitionError, match="unexpected HTTP 201"):
        gae.GitHubApiClient(
            "token", opener=FakeOpener(FakeResponse({}, status=201))
        ).get_json("/repos/a/b/actions/runs/1")
    with pytest.raises(gae.EvidenceAcquisitionError, match="network failure"):
        gae.GitHubApiClient(
            "token", opener=FakeOpener(urllib.error.URLError("private detail"))
        ).get_json("/repos/a/b/actions/runs/1")
    with pytest.raises(gae.EvidenceAcquisitionError, match="invalid JSON"):
        gae.GitHubApiClient(
            "token", opener=FakeOpener(FakeResponse(b"\xff"))
        ).get_json("/repos/a/b/actions/runs/1")

    class ContentTypeHeaders:
        """Expose the email-message content-type interface."""

        @staticmethod
        def get_content_type():
            """Return a trusted JSON media type."""
            return "application/json"

    response = FakeResponse({})
    response.headers = ContentTypeHeaders()
    assert gae.GitHubApiClient(
        "token", opener=FakeOpener(response)
    ).get_json("/repos/a/b/actions/runs/1") == {}

    response = FakeResponse({})
    response.headers = object()
    with pytest.raises(gae.EvidenceAcquisitionError, match="JSON content type"):
        gae.GitHubApiClient(
            "token", opener=FakeOpener(response)
        ).get_json("/repos/a/b/actions/runs/1")


def test_verify_additional_fail_closed_edges():
    """Reject unresolved payload, age, URL, and terminal-state ambiguity."""
    with pytest.raises(gae.EvidenceValidationError, match="job payload"):
        gae.verify_actions_job(
            REPOSITORY,
            run_payload(),
            [],
            observed_at=OBSERVED_AT,
            max_age=timedelta(hours=48),
        )
    with pytest.raises(gae.EvidenceValidationError, match="max_age"):
        gae.verify_actions_job(
            REPOSITORY,
            run_payload(),
            job_payload(),
            observed_at=OBSERVED_AT,
            max_age=timedelta(0),
        )
    with pytest.raises(gae.EvidenceValidationError, match="run URL"):
        verify(
            run=run_payload(
                html_url="https://github.com/other/repo/actions/runs/1"
            )
        )
    with pytest.raises(gae.EvidenceValidationError, match="job URL"):
        verify(
            job=job_payload(
                html_url="https://github.com/other/repo/actions/runs/1/job/2"
            )
        )
    with pytest.raises(gae.EvidenceValidationError, match="job conclusion"):
        verify(
            run=run_payload(conclusion="success"),
            job=job_payload(conclusion="neutral"),
        )

    fallback = verify(
        run=run_payload(name=""),
        job=job_payload(workflow_name="OpenCode Review Dispatch"),
    )
    assert fallback.workflow_name == "OpenCode Review Dispatch"

    current_time = datetime.now(timezone.utc) - timedelta(seconds=1)
    dynamic = gae.verify_actions_job(
        REPOSITORY,
        run_payload(updated_at=current_time.isoformat()),
        job_payload(completed_at=current_time.isoformat()),
        max_age=timedelta(hours=1),
    )
    assert dynamic.observed_at.endswith("Z")

    for observed_at in ("not-a-datetime", datetime(2026, 8, 3)):
        with pytest.raises(gae.EvidenceValidationError, match="observed_at"):
            gae.verify_actions_job(
                REPOSITORY,
                run_payload(),
                job_payload(),
                observed_at=observed_at,
                max_age=timedelta(hours=48),
            )

    empty_optional = gae.verify_actions_job(
        REPOSITORY,
        run_payload(head_branch=None, pull_requests=None),
        job_payload(workflow_name=None, steps=None),
        observed_at=OBSERVED_AT,
        max_age=timedelta(hours=48),
    )
    assert empty_optional.branch_name == ""
    assert empty_optional.failed_step_numbers == ()

    duplicate_prs = verify(
        run=run_payload(
            pull_requests=[
                {"number": 2},
                {"number": 1},
                {"number": 2},
                {"number": None},
            ]
        )
    )
    assert len(duplicate_prs.source_digest_sha256) == 64


def test_scalar_and_collection_validation_edges():
    """Exercise every bounded scalar, step, PR, and digest validation branch."""
    for repository in (None, "owner", "./repo", "owner/.", "owner/.."):
        with pytest.raises(
            gae.EvidenceValidationError, match="repository|path segment"
        ):
            gae._validate_repository(repository)

    assert gae._positive_identifier("2", "id") == 2
    for value in (True, None, "not-an-id", 0, 10**20):
        with pytest.raises(gae.EvidenceValidationError, match="id"):
            gae._positive_identifier(value, "id")

    for value in (None, 3):
        with pytest.raises(gae.EvidenceValidationError, match="text"):
            gae._required_text(value, "field", 4)
    for value in ("", "12345", "x\x00", "x\n"):
        with pytest.raises(gae.EvidenceValidationError, match="field"):
            gae._required_text(value, "field", 4)

    assert gae._optional_text(None, 4) == ""
    assert gae._optional_text("ok", 4) == "ok"
    with pytest.raises(gae.EvidenceValidationError, match="valid ISO"):
        gae._parse_github_time("bad", "time")
    with pytest.raises(gae.EvidenceValidationError, match="timezone"):
        gae._parse_github_time("2026-08-03T00:00:00", "time")
    assert gae._format_timestamp(OBSERVED_AT) == "2026-08-03T00:00:00Z"

    invalid_steps = (
        "not-a-list",
        [1],
        [
            {
                "number": 1,
                "name": "first",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "number": 1,
                "name": "duplicate",
                "status": "completed",
                "conclusion": "success",
            },
        ],
        [
            {
                "number": 1,
                "name": "unknown",
                "status": "completed",
                "conclusion": "mystery",
            }
        ],
    )
    for steps in invalid_steps:
        with pytest.raises(
            gae.EvidenceValidationError, match="steps|step|conclusion"
        ):
            gae._normalize_steps(steps)
    assert gae._normalize_steps(None) == []
    sorted_steps = gae._normalize_steps(
        [
            {
                "number": 2,
                "name": "second",
                "status": "completed",
                "conclusion": None,
            },
            {
                "number": 1,
                "name": "first",
                "status": "completed",
                "conclusion": "success",
            },
        ]
    )
    assert [step["number"] for step in sorted_steps] == [1, 2]

    for pull_requests in ("not-a-list", [1]):
        with pytest.raises(
            gae.EvidenceValidationError, match="pull_request|pull request"
        ):
            gae._pull_request_numbers(pull_requests)
    assert gae._pull_request_numbers(None) == []

    for digest in (None, "bad"):
        with pytest.raises(gae.EvidenceValidationError, match="digest"):
            gae._normalize_digest(digest)
    assert gae._normalize_digest("A" * 64) == "a" * 64


def test_acquisition_rejects_returned_identity_mismatch():
    """Bind requested and returned IDs before classifying API content."""

    class SequenceClient:
        """Return two deterministic payloads in request order."""

        def __init__(self, run, job):
            """Store the run and job responses."""
            self.items = [run, job]

        def get_json(self, path):
            """Return the next response."""
            return self.items.pop(0)

    with pytest.raises(gae.EvidenceValidationError, match="acquired run id"):
        gae.acquire_actions_job(
            SequenceClient(run_payload(id=RUN_ID + 1), job_payload()),
            REPOSITORY,
            RUN_ID,
            JOB_ID,
            observed_at=OBSERVED_AT,
            max_age=timedelta(hours=48),
        )
    with pytest.raises(gae.EvidenceValidationError, match="acquired job id"):
        gae.acquire_actions_job(
            SequenceClient(run_payload(), job_payload(id=JOB_ID + 1)),
            REPOSITORY,
            RUN_ID,
            JOB_ID,
            observed_at=OBSERVED_AT,
            max_age=timedelta(hours=48),
        )


def test_cli_pass_and_validation_error_paths(monkeypatch, capsys):
    """Return stable pass and fail-closed error exit codes."""
    failure = verify()
    passed = gae.ActionsJobEvidence(
        **{
            **failure.__dict__,
            "detector_state": "pass",
            "job_conclusion": "success",
        }
    )
    monkeypatch.setenv("APPGUARDRAIL_GITHUB_TOKEN", "token")
    monkeypatch.setattr(
        gae, "acquire_actions_job", lambda *_args, **_kwargs: passed
    )
    argv = [
        "--repository",
        REPOSITORY,
        "--run-id",
        str(RUN_ID),
        "--job-id",
        str(JOB_ID),
        "--seen-source-digest",
        "a" * 64,
    ]
    assert gae.main(argv) == 0
    assert json.loads(capsys.readouterr().out)["detector_state"] == "pass"

    def raise_validation(*_args, **_kwargs):
        raise gae.EvidenceValidationError("source identity mismatch")

    monkeypatch.setattr(gae, "acquire_actions_job", raise_validation)
    assert gae.main(argv) == 2
    assert json.loads(capsys.readouterr().err) == {
        "error_code": "source_evidence_unavailable",
        "message": "source identity mismatch",
    }
