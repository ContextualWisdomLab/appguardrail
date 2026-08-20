"""Source-bound evidence for GitHub Actions security workflow results."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any

from .issueops import is_security_name

SCHEMA = "appguardrail.source-bound-workflow-evidence.v1"
DETECTOR_FAMILY = "github-actions-security-workflow-failure"
ATOMIC_CAUSE = "security_workflow_control_failure"
CONTROL_OBLIGATION = "security-gate-completion"
PROBE_REF = "github-actions-rest:actions-runs-and-jobs:v1"
ACQUIRER_REF = "appguardrail.github.actions.rest:v1"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_JOB_RESULTS = {"success", "failure", "cancelled", "timed_out", "action_required"}


def _canonical(value: Any) -> str:
    """Serialize trusted evidence deterministically for hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: Any) -> str:
    """Return a SHA-256 digest for a canonical JSON value."""
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value: Any) -> str | None:
    """Return bounded plain text or ``None`` for malformed source data."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 200 or any(ord(char) < 32 for char in value):
        return None
    return value


def _positive_int(value: Any) -> int | None:
    """Return a positive non-boolean integer identifier."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _timestamp(value: Any) -> dt.datetime | None:
    """Parse one timezone-aware ISO timestamp from a source API payload."""
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _safe_now(now: Any) -> dt.datetime | None:
    """Normalize the acquisition clock or reject an unsafe clock value."""
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        return None
    return now.astimezone(dt.UTC)


def _evidence(
    repository: str,
    acquired_at: str | None,
    *,
    status: str,
    reason: str,
    revision: str | None = None,
    artifact_ref: str | None = None,
    artifact_sha256: str | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Build and digest a compact evidence envelope without source logs."""
    result = {
        "schema": SCHEMA,
        "detector_family": DETECTOR_FAMILY,
        "atomic_cause": ATOMIC_CAUSE,
        "control_obligation": CONTROL_OBLIGATION,
        "probe_ref": PROBE_REF,
        "acquirer_ref": ACQUIRER_REF,
        "source_identity": {
            "repository": repository,
            "revision": revision,
            "artifact_ref": artifact_ref,
            "artifact_sha256": artifact_sha256,
            "observed_at": observed_at,
            "acquired_at": acquired_at,
        },
        "assessment": {
            "status": status,
            "reason": reason,
            "confirmed_vulnerability": False,
        },
    }
    result["evidence_digest"] = _sha256(result)
    return result


def _unknown(
    repository: str,
    acquired_at: str | None,
    reason: str,
    *,
    revision: str | None = None,
    artifact_ref: str | None = None,
    artifact_sha256: str | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Return a fail-closed typed unknown result."""
    return _evidence(
        repository,
        acquired_at,
        status="unknown",
        reason=reason,
        revision=revision,
        artifact_ref=artifact_ref,
        artifact_sha256=artifact_sha256,
        observed_at=observed_at,
    )


def _source_payload(
    repository: str,
    run: dict[str, Any],
    job: dict[str, Any],
    run_id: int,
    job_id: int,
    revision: str,
) -> dict[str, Any]:
    """Select bounded source fields; never hash or publish job logs."""
    step_fields = []
    for step in job.get("steps", []):
        if isinstance(step, dict):
            step_fields.append(
                {
                    "number": step.get("number"),
                    "conclusion": step.get("conclusion"),
                }
            )
    return {
        "repository": repository,
        "run": {
            "id": run_id,
            "name": run.get("name"),
            "head_sha": revision,
            "head_branch": run.get("head_branch"),
            "event": run.get("event"),
            "conclusion": run.get("conclusion"),
            "updated_at": run.get("updated_at"),
            "created_at": run.get("created_at"),
        },
        "job": {
            "id": job_id,
            "run_id": job.get("run_id"),
            "name": job.get("name"),
            "workflow_name": job.get("workflow_name"),
            "status": job.get("status"),
            "conclusion": job.get("conclusion"),
            "started_at": job.get("started_at"),
            "completed_at": job.get("completed_at"),
            "steps": step_fields,
        },
    }


def acquire_workflow_evidence(
    repository: str,
    run: dict[str, Any] | None,
    job: dict[str, Any] | None,
    *,
    now: dt.datetime,
    seen_artifact_refs: Iterable[str] = (),
    max_age_hours: int = 48,
) -> dict[str, Any]:
    """Acquire and classify one GitHub Actions source result fail-closed.

    ``run`` and ``job`` are the direct REST responses acquired by the caller.
    Any caller-supplied assessment or digest fields are ignored; the result is
    derived from the job conclusion and a hash of bounded source fields.
    A detected result means the security workflow control failed, not that a
    product vulnerability was independently confirmed.
    """
    acquired = _safe_now(now)
    acquired_at = acquired.isoformat().replace("+00:00", "Z") if acquired else None
    if not isinstance(repository, str) or not _REPO_RE.fullmatch(repository):
        return _unknown("unknown", acquired_at, "missing-source-identity")
    if run is None or job is None:
        return _unknown(repository, acquired_at, "source-unavailable")
    if not isinstance(run, dict) or not isinstance(job, dict):
        return _unknown(repository, acquired_at, "malformed-source-evidence")
    run_id = _positive_int(run.get("id"))
    job_id = _positive_int(job.get("id"))
    if run_id is None or job_id is None:
        return _unknown(repository, acquired_at, "malformed-source-evidence")
    job_run_id = job.get("run_id")
    if job_run_id is not None and job_run_id != run_id:
        return _unknown(repository, acquired_at, "malformed-source-evidence")
    revision = _text(run.get("head_sha"))
    if revision is None:
        return _unknown(repository, acquired_at, "missing-source-identity")
    if not _SHA_RE.fullmatch(revision.lower()):
        return _unknown(repository, acquired_at, "malformed-source-evidence")
    workflow = _text(run.get("name")) or _text(job.get("workflow_name"))
    job_name = _text(job.get("name"))
    if not is_security_name(workflow, job_name):
        return _unknown(
            repository, acquired_at, "unknown-detector-family", revision=revision
        )
    if job_name is None:
        return _unknown(
            repository, acquired_at, "missing-source-identity", revision=revision
        )
    if acquired is None:
        return _unknown(
            repository, None, "malformed-source-evidence", revision=revision
        )
    raw_timestamp = (
        run.get("updated_at") or job.get("completed_at") or run.get("created_at")
    )
    observed = _timestamp(raw_timestamp)
    if observed is None:
        return _unknown(
            repository, acquired_at, "malformed-source-evidence", revision=revision
        )
    observed = observed.astimezone(dt.UTC)
    observed_at = observed.isoformat().replace("+00:00", "Z")
    age = (acquired - observed).total_seconds()
    if age < 0 or age > max_age_hours * 3600:
        return _unknown(
            repository,
            acquired_at,
            "stale-source-evidence",
            revision=revision,
            observed_at=observed_at,
        )
    causes = job.get("failure_causes")
    if causes is not None and (not isinstance(causes, list) or len(causes) != 1):
        return _unknown(
            repository,
            acquired_at,
            "ambiguous-cause-order",
            revision=revision,
            observed_at=observed_at,
        )
    job_conclusion = _text(job.get("conclusion"))
    if job_conclusion is None or job_conclusion.lower() not in _JOB_RESULTS:
        return _unknown(
            repository,
            acquired_at,
            "unknown-detector-result",
            revision=revision,
            observed_at=observed_at,
        )
    run_conclusion = _text(run.get("conclusion"))
    if run_conclusion and run_conclusion.lower() not in _JOB_RESULTS:
        return _unknown(
            repository,
            acquired_at,
            "malformed-source-evidence",
            revision=revision,
            observed_at=observed_at,
        )
    if (
        run_conclusion
        and run_conclusion.lower() == "success"
        and job_conclusion.lower() != "success"
    ):
        return _unknown(
            repository,
            acquired_at,
            "malformed-source-evidence",
            revision=revision,
            observed_at=observed_at,
        )
    if not isinstance(job.get("steps", []), list):
        return _unknown(
            repository,
            acquired_at,
            "malformed-source-evidence",
            revision=revision,
            observed_at=observed_at,
        )
    artifact_ref = f"github-actions://{repository}/runs/{run_id}/jobs/{job_id}"
    if artifact_ref in set(seen_artifact_refs):
        return _unknown(
            repository,
            acquired_at,
            "duplicate-source-artifact",
            revision=revision,
            artifact_ref=artifact_ref,
            observed_at=observed_at,
        )
    artifact_sha256 = _sha256(
        _source_payload(repository, run, job, run_id, job_id, revision)
    )
    status_reason = {
        "success": ("clean", "security-workflow-job-success"),
        "failure": ("detected", "security-workflow-job-failure"),
    }.get(job_conclusion.lower())
    if status_reason is None:
        return _unknown(
            repository,
            acquired_at,
            "unknown-detector-result",
            revision=revision,
            artifact_ref=artifact_ref,
            artifact_sha256=artifact_sha256,
            observed_at=observed_at,
        )
    return _evidence(
        repository,
        acquired_at,
        status=status_reason[0],
        reason=status_reason[1],
        revision=revision,
        artifact_ref=artifact_ref,
        artifact_sha256=artifact_sha256,
        observed_at=observed_at,
    )
