"""Mutation evidence for source-authoritative GitHub Actions predicates."""

from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import appguardrail_core.github_actions_evidence as evidence_module

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "appguardrail_core"
    / "github_actions_evidence.py"
)
OBSERVED_AT = datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc)
REPOSITORY = "ContextualWisdomLab/.github"
RUN_ID = 30_769_144_488
JOB_ID = 91_553_355_284
HEAD_SHA = "2a83043b0239ba827153c934f87e469dba4f96f0"


def run_payload(**overrides):
    """Return an independently specified security workflow run fixture."""
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
    """Return an independently specified security workflow job fixture."""
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
        "steps": [],
    }
    payload.update(overrides)
    return payload


def load_mutant(old: str, new: str):
    """Load exactly one textual production-predicate mutation in isolation."""
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert source.count(old) == 1, f"Mutation target drifted: {old}"
    mutated_source = source.replace(old, new)
    module_name = "appguardrail_core._github_actions_evidence_mutant"
    mutant = types.ModuleType(module_name)
    mutant.__file__ = str(MODULE_PATH)
    mutant.__package__ = "appguardrail_core"
    sys.modules[module_name] = mutant
    try:
        exec(
            compile(mutated_source, str(MODULE_PATH), "exec"),
            mutant.__dict__,
        )
    finally:
        sys.modules.pop(module_name, None)
    return mutant


def verify(module, *, run=None, job=None):
    """Invoke one module's verifier with the fixed independent oracle time."""
    return module.verify_actions_job(
        REPOSITORY,
        run_payload() if run is None else run,
        job_payload() if job is None else job,
        observed_at=OBSERVED_AT,
        max_age=timedelta(hours=48),
    )


def source_identity_oracle(module):
    """Require valid identity to pass and mismatched job/run identity to fail."""
    assert verify(module).detector_state == "failure"
    try:
        verify(module, job=job_payload(run_id=RUN_ID + 1))
    except module.EvidenceValidationError:
        return
    raise AssertionError("mismatched job/run identity was accepted")


def security_obligation_oracle(module):
    """Require a non-security workflow/job pair to be rejected."""
    try:
        verify(
            module,
            run=run_payload(name="Documentation"),
            job=job_payload(name="build", workflow_name="Documentation"),
        )
    except module.EvidenceValidationError:
        return
    raise AssertionError("non-security evidence was accepted")


def outcome_mapping_oracle(module):
    """Require a failed source conclusion to map to detector failure."""
    assert verify(module).detector_state == "failure"


def acquisition_identity_oracle(module):
    """Require exact requested and acquired run/job identifiers."""

    class Client:
        """Return one authoritative run and one authoritative job in order."""

        def __init__(self, run, job):
            """Store the two deterministic source responses."""
            self.items = [run, job]

        def get_json(self, path):
            """Return the next exact source object."""
            return self.items.pop(0)

    assert module.acquire_actions_job(
        Client(run_payload(), job_payload()),
        REPOSITORY,
        RUN_ID,
        JOB_ID,
        observed_at=OBSERVED_AT,
        max_age=timedelta(hours=48),
    ).detector_state == "failure"
    try:
        module.acquire_actions_job(
            Client(run_payload(id=RUN_ID + 1), job_payload()),
            REPOSITORY,
            RUN_ID,
            JOB_ID,
            observed_at=OBSERVED_AT,
            max_age=timedelta(hours=48),
        )
    except module.EvidenceValidationError:
        return
    raise AssertionError("acquired run identity mismatch was accepted")


def test_kills_source_identity_inversion():
    """Prove the independent identity oracle kills an inverted comparison."""
    source_identity_oracle(evidence_module)
    mutant = load_mutant(
        "if job_run_id != run_id:",
        "if job_run_id == run_id:",
    )
    with pytest.raises((AssertionError, mutant.EvidenceValidationError)):
        source_identity_oracle(mutant)


def test_kills_security_obligation_bypass():
    """Prove the security obligation oracle kills a relevance bypass."""
    security_obligation_oracle(evidence_module)
    mutant = load_mutant(
        'if not is_security_name(workflow_name, job.get("workflow_name"), job_name):',
        "if False:",
    )
    with pytest.raises(AssertionError, match="non-security"):
        security_obligation_oracle(mutant)


def test_kills_outcome_mapping_inversion():
    """Prove the outcome oracle kills failure/pass inversion."""
    outcome_mapping_oracle(evidence_module)
    mutant = load_mutant(
        'detector_state = "failure" if is_failure(job_conclusion) else "pass"',
        'detector_state = "pass" if is_failure(job_conclusion) else "failure"',
    )
    with pytest.raises(AssertionError):
        outcome_mapping_oracle(mutant)


def test_kills_acquired_identifier_check_inversion():
    """Prove the acquisition oracle kills requested/returned ID inversion."""
    acquisition_identity_oracle(evidence_module)
    mutant = load_mutant(
        'if _positive_identifier(run.get("id"), "run id") != normalized_run_id:',
        'if _positive_identifier(run.get("id"), "run id") == normalized_run_id:',
    )
    with pytest.raises((AssertionError, mutant.EvidenceValidationError)):
        acquisition_identity_oracle(mutant)
