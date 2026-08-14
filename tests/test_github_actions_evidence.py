"""Tests for source-authoritative GitHub Actions job evidence."""

from __future__ import annotations

import io
import json
import urllib.error
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from appguardrail_core.github_actions_evidence import (
    ActionsJobEvidence,
    EvidenceAcquisitionError,
    EvidenceValidationError,
    GitHubApiClient,
    acquire_actions_job,
    main,
    verify_actions_job,
)

OBSERVED_AT = datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc)
REPOSITORY = "ContextualWisdomLab/.github"
RUN_ID = 30_769_144_488
JOB_ID = 91_553_355_284
HEAD_SHA = "2a83043b0239ba827153c934f87e469dba4f96f0"


def run_payload(**overrides):
    """Return a #815-shaped GitHub Actions run payload."""
    payload = {
        "id": RUN_ID,
        "name": (
            "OpenCode Review Dispatch "
            "ContextualWisdomLab/.github#701@3a15867168d39a248b92c14f6db0e63584e8dc22"
        ),
        "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        "head_sha": HEAD_SHA,
        "head_branch": "main",
        "event": "repository_dispatch",
        "status": "completed",
        "conclusion": "failure",
        "created_at": "2026-08-02T23:40:00Z",
        "updated_at": "2026-08-02T23:44:00Z",
        "pull_requests": [],
    }
    payload.update(overrides)
    return payload


def job_payload(**overrides):
    """Return a #815-shaped GitHub Actions job payload."""
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
        "started_at": "2026-08-02T23:41:00Z",
        "completed_at": "2026-08-02T23:43:30Z",
        "steps": [
            {
                "number": 18,
                "name": "Run bounded review",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "number": 19,
                "name": "Publish review",
                "status": "completed",
                "conclusion": "failure",
            },
        ],
    }
    payload.update(overrides)
    return payload


def verify(run=None, job=None, **kwargs):
    """Verify one fixture with deterministic observation time and freshness."""
    return verify_actions_job(
        REPOSITORY,
        run_payload() if run is None else run,
        job_payload() if job is None else job,
        observed_at=OBSERVED_AT,
        max_age=timedelta(hours=48),
        **kwargs,
    )


def test_verifies_source_authoritative_failure():
    """Bind a real-world failure shape to immutable source identity."""
    evidence = verify()

    assert isinstance(evidence, ActionsJobEvidence)
    assert evidence.detector_state == "failure"
    assert evidence.repository == REPOSITORY
    assert evidence.run_id == RUN_ID
    assert evidence.job_id == JOB_ID
    assert evidence.head_sha == HEAD_SHA
    assert evidence.failed_step_numbers == (19,)
    assert evidence.probe_ref == "github_actions_job_v1"
    assert evidence.acquirer_ref == "github_rest_api_v2022_11_28"
    assert len(evidence.source_digest_sha256) == 64
    assert evidence.to_dict()["failed_step_numbers"] == [19]


def test_verifies_pass_and_digest_is_mapping_order_independent():
    """Return pass for a successful security job and hash canonical content."""
    run = run_payload(conclusion="success")
    job = job_payload(
        conclusion="success",
        steps=[
            {
                "conclusion": "success",
                "status": "completed",
                "name": "Publish review",
                "number": 19,
            }
        ],
    )
    reversed_run = dict(reversed(list(run.items())))
    reversed_job = dict(reversed(list(job.items())))

    first = verify(run=run, job=job)
    second = verify(run=reversed_run, job=reversed_job)

    assert first.detector_state == "pass"
    assert first.source_digest_sha256 == second.source_digest_sha256


def test_cancelled_security_job_is_a_verified_failure():
    """Treat a completed cancelled scanner job as a non-passing security result."""
    run = run_payload(
        name="Strix Security Scan ContextualWisdomLab/newsdom-api#501@" + HEAD_SHA,
        conclusion="cancelled",
    )
    job = job_payload(
        name="strix",
        workflow_name="Strix Security Scan",
        conclusion="cancelled",
    )

    assert verify(run=run, job=job).detector_state == "failure"


@pytest.mark.parametrize(
    ("repository", "run", "job", "error"),
    [
        ("ContextualWisdomLab/../evil", run_payload(), job_payload(), "repository"),
        (
            REPOSITORY,
            run_payload(id=RUN_ID + 1),
            job_payload(),
            "run id",
        ),
        (
            REPOSITORY,
            run_payload(),
            job_payload(run_id=RUN_ID + 1),
            "job run id",
        ),
        (
            REPOSITORY,
            run_payload(head_sha="abc123"),
            job_payload(),
            "head SHA",
        ),
        (
            REPOSITORY,
            run_payload(
                html_url=f"https://evil.example/{REPOSITORY}/actions/runs/{RUN_ID}"
            ),
            job_payload(),
            "run URL",
        ),
        (
            REPOSITORY,
            run_payload(),
            job_payload(
                html_url=f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/job/1"
            ),
            "job URL",
        ),
        (
            REPOSITORY,
            run_payload(status="queued"),
            job_payload(),
            "run status",
        ),
        (
            REPOSITORY,
            run_payload(),
            job_payload(status="in_progress"),
            "job status",
        ),
        (
            REPOSITORY,
            run_payload(conclusion="neutral"),
            job_payload(conclusion="neutral"),
            "conclusion",
        ),
        (
            REPOSITORY,
            run_payload(name="Documentation"),
            job_payload(name="build", workflow_name="Documentation"),
            "security-relevant",
        ),
    ],
)
def test_rejects_identity_and_state_ambiguity(repository, run, job, error):
    """Fail closed when the exact source identity or terminal state is ambiguous."""
    with pytest.raises(EvidenceValidationError, match=error):
        verify_actions_job(
            repository,
            run,
            job,
            observed_at=OBSERVED_AT,
            max_age=timedelta(hours=48),
        )


@pytest.mark.parametrize("payload_name", ["run", "job"])
def test_rejects_non_object_source_payload(payload_name):
    """Reject JSON arrays and scalars instead of interpreting caller assertions."""
    run = [] if payload_name == "run" else run_payload()
    job = [] if payload_name == "job" else job_payload()

    with pytest.raises(EvidenceValidationError, match=f"{payload_name} payload"):
        verify(run=run, job=job)


def test_rejects_future_and_stale_evidence():
    """Do not accept future-dated or replayed source evidence silently."""
    with pytest.raises(EvidenceValidationError, match="future"):
        verify(
            run=run_payload(updated_at="2026-08-03T00:00:01Z"),
            job=job_payload(completed_at="2026-08-03T00:00:01Z"),
        )

    with pytest.raises(EvidenceValidationError, match="stale"):
        verify_actions_job(
            REPOSITORY,
            run_payload(updated_at="2026-07-01T00:00:00Z"),
            job_payload(completed_at="2026-07-01T00:00:00Z"),
            observed_at=OBSERVED_AT,
            max_age=timedelta(hours=48),
        )

    with pytest.raises(EvidenceValidationError, match="max_age"):
        verify_actions_job(
            REPOSITORY,
            run_payload(),
            job_payload(),
            observed_at=OBSERVED_AT,
            max_age=timedelta(0),
        )


def test_rejects_duplicate_source_digest():
    """Prevent a verified source artifact from being ingested twice."""
    evidence = verify()

    with pytest.raises(EvidenceValidationError, match="duplicate"):
        verify(seen_source_digests={evidence.source_digest_sha256})


class FakeResponse:
    """Bounded in-memory HTTP response used by the REST client tests."""

    def __init__(self, payload, content_type="application/json", status=200):
        """Encode payload and expose the subset of HTTPResponse used in production."""
        self.body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.headers = {"content-type": content_type}
        self.status = status

    def read(self, amount=-1):
        """Read at most the requested byte count."""
        return self.body if amount < 0 else self.body[:amount]

    def __enter__(self):
        """Enter the response context."""
        return self

    def __exit__(self, exc_type, exc, traceback):
        """Exit without suppressing errors."""
        return False


class FakeOpener:
    """Record requests and return queued responses or exceptions."""

    def __init__(self, *results):
        """Store deterministic results for subsequent open calls."""
        self.results = list(results)
        self.requests = []

    def open(self, request, timeout):
        """Return or raise the next configured result."""
        self.requests.append((request, timeout))
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def test_client_fetches_bounded_json_with_scoped_auth_header():
    """Acquire JSON only from the pinned API without exposing the token."""
    opener = FakeOpener(FakeResponse(run_payload()))
    client = GitHubApiClient("secret-token", opener=opener)

    payload = client.get_json(f"/repos/{REPOSITORY}/actions/runs/{RUN_ID}")

    request, timeout = opener.requests[0]
    assert payload["id"] == RUN_ID
    assert request.full_url == (
        f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{RUN_ID}"
    )
    assert request.get_header("Authorization") == "Bearer secret-token"
    assert request.get_header("X-github-api-version") == "2022-11-28"
    assert timeout == 30
    assert "secret-token" not in json.dumps(payload)


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (FakeResponse({}, content_type="text/plain"), "JSON content type"),
        (FakeResponse([], content_type="application/json"), "JSON object"),
        (FakeResponse(b"x" * (2 * 1024 * 1024 + 1)), "response limit"),
        (FakeResponse(b"{"), "invalid JSON"),
    ],
)
def test_client_rejects_untrusted_response_shapes(response, error):
    """Reject non-JSON, oversized, invalid, and non-object API responses."""
    client = GitHubApiClient("token", opener=FakeOpener(response))

    with pytest.raises(EvidenceAcquisitionError, match=error):
        client.get_json(f"/repos/{REPOSITORY}/actions/runs/{RUN_ID}")


def test_client_rejects_invalid_configuration_and_network_errors():
    """Pin origin and paths and return sanitized acquisition failures."""
    with pytest.raises(ValueError, match="token"):
        GitHubApiClient(" ")
    with pytest.raises(ValueError, match="API root"):
        GitHubApiClient("token", api_root="https://example.com")

    client = GitHubApiClient("token", opener=FakeOpener(FakeResponse({})))
    with pytest.raises(ValueError, match="path"):
        client.get_json("https://evil.example/api")

    http_error = urllib.error.HTTPError(
        "https://api.github.com", 403, "Forbidden", {}, io.BytesIO(b"secret-token")
    )
    client = GitHubApiClient("secret-token", opener=FakeOpener(http_error))
    with pytest.raises(EvidenceAcquisitionError, match="HTTP 403") as exc_info:
        client.get_json(f"/repos/{REPOSITORY}/actions/runs/{RUN_ID}")
    assert "secret-token" not in str(exc_info.value)

    client = GitHubApiClient(
        "secret-token", opener=FakeOpener(urllib.error.URLError("secret-token"))
    )
    with pytest.raises(EvidenceAcquisitionError, match="network failure") as exc_info:
        client.get_json(f"/repos/{REPOSITORY}/actions/runs/{RUN_ID}")
    assert "secret-token" not in str(exc_info.value)


def test_acquire_actions_job_uses_exact_source_endpoints():
    """Fetch the authoritative run and job before evaluating the outcome."""
    opener = FakeOpener(FakeResponse(run_payload()), FakeResponse(job_payload()))
    client = GitHubApiClient("token", opener=opener)

    evidence = acquire_actions_job(
        client,
        REPOSITORY,
        RUN_ID,
        JOB_ID,
        observed_at=OBSERVED_AT,
        max_age=timedelta(hours=48),
    )

    assert evidence.detector_state == "failure"
    assert [request.full_url for request, _timeout in opener.requests] == [
        f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{RUN_ID}",
        f"https://api.github.com/repos/{REPOSITORY}/actions/jobs/{JOB_ID}",
    ]


def test_cli_emits_evidence_and_uses_decision_exit_codes(monkeypatch, capsys):
    """Expose pass/failure as machine-readable output and stable exit codes."""
    failure = verify()
    passed = ActionsJobEvidence(
        **{**failure.__dict__, "detector_state": "pass", "job_conclusion": "success"}
    )
    observed = []

    class FakeClient:
        def __init__(self, token):
            observed.append(token)

    monkeypatch.setenv("APPGUARDRAIL_GITHUB_TOKEN", "scoped-token")
    monkeypatch.setattr(
        "appguardrail_core.github_actions_evidence.GitHubApiClient", FakeClient
    )
    monkeypatch.setattr(
        "appguardrail_core.github_actions_evidence.acquire_actions_job",
        lambda *_args, **_kwargs: passed,
    )

    argv = [
        "--repository",
        REPOSITORY,
        "--run-id",
        str(RUN_ID),
        "--job-id",
        str(JOB_ID),
        "--max-age-hours",
        "48",
    ]
    assert main(argv) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["detector_state"] == "pass"
    assert observed == ["scoped-token"]

    monkeypatch.setattr(
        "appguardrail_core.github_actions_evidence.acquire_actions_job",
        lambda *_args, **_kwargs: failure,
    )
    assert main(argv) == 1
    assert json.loads(capsys.readouterr().out)["detector_state"] == "failure"


def test_cli_fails_closed_without_token_or_on_validation_error(monkeypatch, capsys):
    """Return exit 2 with bounded JSON errors for unavailable source evidence."""
    monkeypatch.delenv("APPGUARDRAIL_GITHUB_TOKEN", raising=False)
    argv = [
        "--repository",
        REPOSITORY,
        "--run-id",
        str(RUN_ID),
        "--job-id",
        str(JOB_ID),
    ]
    assert main(argv) == 2
    assert json.loads(capsys.readouterr().err)["error_code"] == "missing_token"

    monkeypatch.setenv("APPGUARDRAIL_GITHUB_TOKEN", "token")
    monkeypatch.setattr(
        "appguardrail_core.github_actions_evidence.acquire_actions_job",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            EvidenceValidationError("source identity mismatch")
        ),
    )
    assert main(argv) == 2
    error = json.loads(capsys.readouterr().err)
    assert error == {
        "error_code": "source_evidence_unavailable",
        "message": "source identity mismatch",
    }
