"""Acquire and verify source-authoritative GitHub Actions job evidence.

The verifier deliberately accepts GitHub run and job API objects rather than a
caller-provided Boolean decision. It binds their exact repository, run, job,
commit, terminal state, and freshness into a deterministic SHA-256 evidence
identity suitable for audit and duplicate prevention.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from appguardrail_core.issueops import is_failure, is_security_name

API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
PROBE_REF = "github_actions_job_v1"
ACQUIRER_REF = "github_rest_api_v2022_11_28"
SCHEMA_VERSION = "1.0"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_IDENTIFIER_DIGITS = 20
MAX_AGE_HOURS = 24 * 365 * 10
_REPOSITORY_RE = re.compile(
    r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z"
)
_HEAD_SHA_RE = re.compile(r"[0-9a-fA-F]{40}\Z")
_SOURCE_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED_CONCLUSIONS = {"success", "failure", "cancelled", "timed_out", "action_required"}
_ALLOWED_STEP_CONCLUSIONS = _ALLOWED_CONCLUSIONS | {"skipped", "neutral", "stale", "startup_failure", ""}


class EvidenceValidationError(ValueError):
    """Raised when acquired source evidence is ambiguous, stale, or invalid."""


class EvidenceAcquisitionError(RuntimeError):
    """Raised when the authoritative GitHub source cannot be acquired safely."""


@dataclass(frozen=True)
class ActionsJobEvidence:
    """Immutable normalized evidence for one verified GitHub Actions job."""

    schema_version: str
    probe_ref: str
    acquirer_ref: str
    repository: str
    workflow_name: str
    job_name: str
    run_id: int
    job_id: int
    head_sha: str
    branch_name: str
    event_name: str
    run_url: str
    job_url: str
    job_conclusion: str
    detector_state: str
    failed_step_numbers: tuple[int, ...]
    source_updated_at: str
    observed_at: str
    source_digest_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible evidence representation."""
        payload = asdict(self)
        payload["failed_step_numbers"] = list(self.failed_step_numbers)
        return payload


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so authenticated requests cannot change origins."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return no redirected request and let urllib surface the response."""
        return None


class GitHubApiClient:
    """Bounded GitHub REST client pinned to the public API origin."""

    def __init__(
        self,
        token: str,
        *,
        api_root: str = API_ROOT,
        opener: Any | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        """Initialize a client with one scoped token and bounded I/O limits."""
        if not isinstance(token, str) or not token.strip():
            raise ValueError("GitHub token must be non-empty")
        if any(ord(character) < 32 or ord(character) == 127 for character in token):
            raise ValueError("GitHub token must not contain HTTP control characters")
        if api_root.rstrip("/") != API_ROOT:
            raise ValueError("GitHub API root must be https://api.github.com")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._token = token.strip()
        self._api_root = API_ROOT
        self._opener = opener or urllib.request.build_opener(_NoRedirect)
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes

    def get_json(self, path: str) -> dict[str, Any]:
        """Fetch one bounded JSON object from an allowed GitHub Actions path."""
        if not isinstance(path, str) or not re.fullmatch(
            r"/repos/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/actions/(?:runs|jobs)/[1-9][0-9]{0,19}",
            path,
        ):
            raise ValueError("GitHub API path is not an allowed Actions resource path")
        request = urllib.request.Request(  # noqa: S310 - exact fixed GitHub origin
            f"{self._api_root}{path}",
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "appguardrail-actions-evidence",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with self._opener.open(
                request, timeout=self._timeout_seconds
            ) as response:  # noqa: S310 - exact fixed GitHub origin
                status = int(getattr(response, "status", 200))
                if status != 200:
                    raise EvidenceAcquisitionError(
                        f"GitHub API returned unexpected HTTP {status}"
                    )
                content_type = _content_type(response.headers)
                if "application/json" not in content_type.lower():
                    raise EvidenceAcquisitionError(
                        "GitHub API response did not use a JSON content type"
                    )
                body = response.read(self._max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            raise EvidenceAcquisitionError(
                f"GitHub API request failed with HTTP {exc.code}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise EvidenceAcquisitionError("GitHub API network failure") from exc
        if len(body) > self._max_response_bytes:
            raise EvidenceAcquisitionError("GitHub API response exceeded the response limit")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceAcquisitionError("GitHub API returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise EvidenceAcquisitionError("GitHub API response must be a JSON object")
        return payload


def verify_actions_job(
    repository: str,
    run: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    observed_at: datetime | None = None,
    max_age: timedelta = timedelta(hours=48),
    seen_source_digests: Iterable[str] = (),
) -> ActionsJobEvidence:
    """Validate and classify exact GitHub Actions run and job API objects."""
    normalized_repository = _validate_repository(repository)
    if not isinstance(run, Mapping):
        raise EvidenceValidationError("run payload must be a JSON object")
    if not isinstance(job, Mapping):
        raise EvidenceValidationError("job payload must be a JSON object")
    if not isinstance(max_age, timedelta) or max_age <= timedelta(0):
        raise EvidenceValidationError("max_age must be a positive timedelta")

    run_id = _positive_identifier(run.get("id"), "run id")
    job_id = _positive_identifier(job.get("id"), "job id")
    job_run_id = _positive_identifier(job.get("run_id"), "job run id")
    if job_run_id != run_id:
        raise EvidenceValidationError("job run id does not match run id")

    run_url = _required_text(run.get("html_url"), "run URL", 500)
    expected_run_url = (
        f"https://github.com/{normalized_repository}/actions/runs/{run_id}"
    )
    if run_url != expected_run_url:
        raise EvidenceValidationError("run id and run URL do not match")

    job_url = _required_text(job.get("html_url"), "job URL", 600)
    expected_job_url = f"{expected_run_url}/job/{job_id}"
    if job_url != expected_job_url:
        raise EvidenceValidationError("job URL does not match repository, run, and job ids")

    head_sha = _required_text(run.get("head_sha"), "head SHA", 40).lower()
    if not _HEAD_SHA_RE.fullmatch(head_sha):
        raise EvidenceValidationError("head SHA must contain exactly 40 hexadecimal characters")

    run_status = _required_text(run.get("status"), "run status", 40).lower()
    if run_status != "completed":
        raise EvidenceValidationError("run status must be completed")
    job_status = _required_text(job.get("status"), "job status", 40).lower()
    if job_status != "completed":
        raise EvidenceValidationError("job status must be completed")

    run_conclusion = _required_text(run.get("conclusion"), "run conclusion", 40).lower()
    job_conclusion = _required_text(job.get("conclusion"), "job conclusion", 40).lower()
    if run_conclusion not in _ALLOWED_CONCLUSIONS:
        raise EvidenceValidationError("run conclusion is unsupported")
    if job_conclusion not in _ALLOWED_CONCLUSIONS:
        raise EvidenceValidationError("job conclusion is unsupported")

    workflow_name = _required_text(
        run.get("name") or job.get("workflow_name"), "workflow name", 500
    )
    job_name = _required_text(job.get("name"), "job name", 500)
    if not is_security_name(workflow_name, job.get("workflow_name"), job_name):
        raise EvidenceValidationError("job is not security-relevant")

    observed = _normalize_observed_at(observed_at)
    run_updated_at = _parse_github_time(run.get("updated_at"), "run updated_at")
    job_completed_at = _parse_github_time(job.get("completed_at"), "job completed_at")
    source_updated_at = max(run_updated_at, job_completed_at)
    if source_updated_at > observed:
        raise EvidenceValidationError("source evidence is future-dated")
    if observed - source_updated_at > max_age:
        raise EvidenceValidationError("source evidence is stale")

    steps = _normalize_steps(job.get("steps"))
    branch_name = _optional_text(run.get("head_branch"), 255)
    event_name = _required_text(run.get("event"), "event name", 100)
    source_projection = {
        "repository": normalized_repository,
        "run": {
            "id": run_id,
            "name": workflow_name,
            "html_url": run_url,
            "head_sha": head_sha,
            "head_branch": branch_name,
            "event": event_name,
            "status": run_status,
            "conclusion": run_conclusion,
            "updated_at": _format_timestamp(run_updated_at),
            "pull_request_numbers": _pull_request_numbers(run.get("pull_requests")),
        },
        "job": {
            "id": job_id,
            "run_id": job_run_id,
            "name": job_name,
            "workflow_name": _optional_text(job.get("workflow_name"), 500),
            "html_url": job_url,
            "status": job_status,
            "conclusion": job_conclusion,
            "completed_at": _format_timestamp(job_completed_at),
            "steps": steps,
        },
    }
    canonical = json.dumps(
        source_projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    source_digest = hashlib.sha256(canonical).hexdigest()
    normalized_seen = {_normalize_digest(value) for value in seen_source_digests}
    if source_digest in normalized_seen:
        raise EvidenceValidationError("duplicate source evidence digest")

    failed_steps = tuple(
        step["number"]
        for step in steps
        if is_failure(step["conclusion"])
    )
    detector_state = "failure" if is_failure(job_conclusion) else "pass"
    return ActionsJobEvidence(
        schema_version=SCHEMA_VERSION,
        probe_ref=PROBE_REF,
        acquirer_ref=ACQUIRER_REF,
        repository=normalized_repository,
        workflow_name=workflow_name,
        job_name=job_name,
        run_id=run_id,
        job_id=job_id,
        head_sha=head_sha,
        branch_name=branch_name,
        event_name=event_name,
        run_url=run_url,
        job_url=job_url,
        job_conclusion=job_conclusion,
        detector_state=detector_state,
        failed_step_numbers=failed_steps,
        source_updated_at=_format_timestamp(source_updated_at),
        observed_at=_format_timestamp(observed),
        source_digest_sha256=source_digest,
    )


def acquire_actions_job(
    client: GitHubApiClient,
    repository: str,
    run_id: int,
    job_id: int,
    *,
    observed_at: datetime | None = None,
    max_age: timedelta = timedelta(hours=48),
    seen_source_digests: Iterable[str] = (),
) -> ActionsJobEvidence:
    """Acquire an exact run/job pair from GitHub and verify its source identity."""
    normalized_repository = _validate_repository(repository)
    normalized_run_id = _positive_identifier(run_id, "run id")
    normalized_job_id = _positive_identifier(job_id, "job id")
    run = client.get_json(
        f"/repos/{normalized_repository}/actions/runs/{normalized_run_id}"
    )
    job = client.get_json(
        f"/repos/{normalized_repository}/actions/jobs/{normalized_job_id}"
    )
    if _positive_identifier(run.get("id"), "run id") != normalized_run_id:
        raise EvidenceValidationError("acquired run id does not match requested run id")
    if _positive_identifier(job.get("id"), "job id") != normalized_job_id:
        raise EvidenceValidationError("acquired job id does not match requested job id")
    return verify_actions_job(
        normalized_repository,
        run,
        job,
        observed_at=observed_at,
        max_age=max_age,
        seen_source_digests=seen_source_digests,
    )


def main(argv: list[str] | None = None) -> int:
    """Run the source-evidence verifier and return a stable decision exit code."""
    parser = argparse.ArgumentParser(
        prog="appguardrail-actions-evidence",
        description="Acquire and verify one exact GitHub Actions security job.",
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--job-id", required=True, type=int)
    parser.add_argument("--max-age-hours", type=float, default=48.0)
    parser.add_argument("--seen-source-digest", action="append", default=[])
    args = parser.parse_args(argv)

    if (
        not math.isfinite(args.max_age_hours)
        or args.max_age_hours <= 0
        or args.max_age_hours > MAX_AGE_HOURS
    ):
        _write_error(
            "invalid_max_age",
            f"max_age_hours must be finite and within (0, {MAX_AGE_HOURS}]",
        )
        return 2

    token = os.environ.get("APPGUARDRAIL_GITHUB_TOKEN", "").strip()
    if not token:
        _write_error("missing_token", "APPGUARDRAIL_GITHUB_TOKEN is required")
        return 2
    try:
        client = GitHubApiClient(token)
        evidence = acquire_actions_job(
            client,
            args.repository,
            args.run_id,
            args.job_id,
            max_age=timedelta(hours=args.max_age_hours),
            seen_source_digests=args.seen_source_digest,
        )
    except (EvidenceAcquisitionError, EvidenceValidationError, ValueError) as exc:
        _write_error("source_evidence_unavailable", str(exc))
        return 2
    print(json.dumps(evidence.to_dict(), sort_keys=True, ensure_ascii=False))
    return 1 if evidence.detector_state == "failure" else 0


def _content_type(headers: Any) -> str:
    """Return a response media type without trusting arbitrary header objects."""
    if hasattr(headers, "get_content_type"):
        return str(headers.get_content_type())
    if hasattr(headers, "get"):
        return str(headers.get("content-type", ""))
    return ""


def _validate_repository(repository: Any) -> str:
    """Validate and return one exact bounded GitHub owner/name identifier."""
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        raise EvidenceValidationError("repository must be an exact owner/name identifier")
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise EvidenceValidationError("repository contains an invalid path segment")
    return repository


def _positive_identifier(value: Any, label: str) -> int:
    """Validate and return a positive bounded integer identifier."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise EvidenceValidationError(f"{label} must be a positive integer")
    if isinstance(value, str) and (not value.isascii() or not value.isdigit()):
        raise EvidenceValidationError(f"{label} must be a positive integer")
    normalized = int(value)
    if normalized <= 0 or len(str(normalized)) > MAX_IDENTIFIER_DIGITS:
        raise EvidenceValidationError(
            f"{label} must be a positive integer of at most {MAX_IDENTIFIER_DIGITS} digits"
        )
    return normalized


def _required_text(value: Any, label: str, max_length: int) -> str:
    """Validate one bounded non-empty string without line controls."""
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{label} must be text")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise EvidenceValidationError(f"{label} is empty, oversized, or contains controls")
    normalized = value.strip()
    if not normalized or len(normalized) > max_length:
        raise EvidenceValidationError(f"{label} is empty, oversized, or contains controls")
    return normalized


def _optional_text(value: Any, max_length: int) -> str:
    """Return a validated optional string using the empty string for null."""
    if value is None:
        return ""
    return _required_text(value, "optional text", max_length)


def _parse_github_time(value: Any, label: str) -> datetime:
    """Parse a timezone-aware GitHub timestamp and normalize it to UTC."""
    text = _required_text(value, label, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceValidationError(f"{label} is not a valid ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise EvidenceValidationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _normalize_observed_at(value: datetime | None) -> datetime:
    """Return a timezone-aware UTC observation timestamp."""
    observed = value or datetime.now(timezone.utc)
    if not isinstance(observed, datetime) or observed.tzinfo is None:
        raise EvidenceValidationError("observed_at must be timezone-aware")
    return observed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    """Serialize a datetime as canonical UTC ISO 8601 text."""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_steps(value: Any) -> list[dict[str, Any]]:
    """Validate, sort, and normalize non-empty terminal GitHub job steps."""
    if not isinstance(value, list):
        raise EvidenceValidationError("job steps must be a non-empty list")
    if not value:
        raise EvidenceValidationError("job steps must contain at least one completed step")
    normalized: list[dict[str, Any]] = []
    seen_numbers: set[int] = set()
    for raw_step in value:
        if not isinstance(raw_step, Mapping):
            raise EvidenceValidationError("each job step must be a JSON object")
        number = _positive_identifier(raw_step.get("number"), "step number")
        if number in seen_numbers:
            raise EvidenceValidationError("job step numbers must be unique")
        seen_numbers.add(number)
        status = _required_text(raw_step.get("status"), "step status", 40).lower()
        if status != "completed":
            raise EvidenceValidationError("step status must be completed")
        conclusion = str(raw_step.get("conclusion") or "").strip().lower()
        if conclusion not in _ALLOWED_STEP_CONCLUSIONS:
            raise EvidenceValidationError("step conclusion is unsupported")
        normalized.append(
            {
                "number": number,
                "name": _required_text(raw_step.get("name"), "step name", 500),
                "status": status,
                "conclusion": conclusion,
            }
        )
    return sorted(normalized, key=lambda step: step["number"])


def _pull_request_numbers(value: Any) -> list[int]:
    """Return sorted unique pull-request numbers from a GitHub run payload."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise EvidenceValidationError("pull_requests must be a list")
    numbers: set[int] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise EvidenceValidationError("each pull request must be a JSON object")
        number = item.get("number")
        if number is not None:
            numbers.add(_positive_identifier(number, "pull request number"))
    return sorted(numbers)


def _normalize_digest(value: Any) -> str:
    """Validate and normalize one lower-case SHA-256 evidence digest."""
    if not isinstance(value, str):
        raise EvidenceValidationError("source digest must be text")
    normalized = value.strip().lower()
    if not _SOURCE_DIGEST_RE.fullmatch(normalized):
        raise EvidenceValidationError("source digest must be 64 hexadecimal characters")
    return normalized


def _write_error(error_code: str, message: str) -> None:
    """Write one stable machine-readable error object to standard error."""
    payload = {"error_code": error_code, "message": message}
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False), file=sys.stderr)
