"""Tests for source-authoritative GitHub Actions evidence."""

from __future__ import annotations

import importlib.util
import json
from argparse import Namespace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from appguardrail_core import issueops
from appguardrail_core.controlplane import add_scan, connect, create_org, get_scan
from appguardrail_core.source_evidence import acquire_workflow_evidence

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "source_evidence"
MODULE_PATH = ROOT / "scripts" / "ci" / "collect_org_security_failures.py"
SPEC = importlib.util.spec_from_file_location("source_bound_collector", MODULE_PATH)
assert SPEC and SPEC.loader
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)

NOW = datetime(2026, 8, 20, 1, 0, tzinfo=UTC)


def fixture(name: str) -> tuple[dict, dict]:
    """Load one bounded source fixture without an expected-answer field."""
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload["run"], payload["job"]


def test_failure_fixture_is_detected_from_acquired_job_conclusion():
    """A failed security job is typed as a control failure, not a vulnerability."""
    run, job = fixture("strix-failure.json")

    evidence = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", run, job, now=NOW
    )

    assert evidence["assessment"] == {
        "status": "detected",
        "reason": "security-workflow-job-failure",
        "confirmed_vulnerability": False,
    }
    assert evidence["atomic_cause"] == "security_workflow_control_failure"
    assert evidence["probe_ref"] == "github-actions-rest:actions-runs-and-jobs:v1"
    assert evidence["acquirer_ref"] == "appguardrail.github.actions.rest:v1"
    assert evidence["source_identity"]["revision"] == run["head_sha"]
    assert "logs" not in evidence
    assert "PRIVATE_SOURCE_SECRET" not in json.dumps(evidence)


def test_success_fixture_is_a_clean_result_from_the_same_path():
    """A completed successful job is a clean result, not an absent result."""
    run, job = fixture("strix-success.json")

    evidence = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", run, job, now=NOW
    )

    assert evidence["assessment"]["status"] == "clean"
    assert evidence["assessment"]["reason"] == "security-workflow-job-success"
    assert evidence["assessment"]["confirmed_vulnerability"] is False


def test_public_historical_failure_fixture_is_source_authoritative():
    """Replay the public #815 source run with an independently authored oracle."""
    run, job = fixture("real-opencode-failure.json")

    evidence = acquire_workflow_evidence(
        "ContextualWisdomLab/.github",
        run,
        job,
        now=datetime(2026, 8, 2, 23, 0, tzinfo=UTC),
    )

    assert evidence["assessment"] == {
        "status": "detected",
        "reason": "security-workflow-job-failure",
        "confirmed_vulnerability": False,
    }
    assert evidence["source_identity"]["artifact_ref"] == (
        "github-actions://ContextualWisdomLab/.github/runs/30769144488/jobs/91553355284"
    )


def test_public_historical_success_job_is_a_true_negative_for_the_same_run():
    """A successful sibling job remains clean despite the workflow run failing elsewhere."""
    run, job = fixture("real-opencode-success.json")

    evidence = acquire_workflow_evidence(
        "ContextualWisdomLab/.github",
        run,
        job,
        now=datetime(2026, 8, 2, 23, 0, tzinfo=UTC),
    )

    assert evidence["assessment"]["status"] == "clean"
    assert evidence["assessment"]["reason"] == "security-workflow-job-success"


@pytest.mark.parametrize(
    ("label", "run_change", "job_change", "expected_reason"),
    [
        ("unavailable", None, None, "source-unavailable"),
        ("missing-sha", {"head_sha": ""}, {}, "missing-source-identity"),
        ("invalid-sha", {"head_sha": "not-a-sha"}, {}, "malformed-source-evidence"),
        ("run-job-mismatch", {}, {"run_id": 999}, "malformed-source-evidence"),
        ("missing-run-id", {}, {"run_id": None}, "malformed-source-evidence"),
        (
            "ambiguous-cause",
            {},
            {"failure_causes": ["scanner", "runner"]},
            "ambiguous-cause-order",
        ),
        (
            "unknown-conclusion",
            {},
            {"conclusion": "neutral"},
            "unknown-detector-result",
        ),
    ],
)
def test_malformed_or_ambiguous_source_fails_closed(
    label, run_change, job_change, expected_reason
):
    """Malformed source evidence never becomes a clean or confirmed finding."""
    run, job = fixture("strix-failure.json")
    if run_change:
        run.update(run_change)
    if job_change:
        job.update(job_change)
    if label == "unavailable":
        run = None
        job = None

    evidence = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", run, job, now=NOW
    )

    assert evidence["assessment"]["status"] == "unknown"
    assert evidence["assessment"]["reason"] == expected_reason
    assert evidence["assessment"]["confirmed_vulnerability"] is False


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("bad-payload-type", "malformed-source-evidence"),
        ("bad-repository", "missing-source-identity"),
        ("bad-id", "malformed-source-evidence"),
        ("missing-revision", "missing-source-identity"),
        ("unknown-family", "unknown-detector-family"),
        ("missing-job-name", "missing-source-identity"),
        ("bad-clock", "malformed-source-evidence"),
        ("bad-timestamp", "malformed-source-evidence"),
        ("missing-timestamp", "malformed-source-evidence"),
        ("run-success-job-failure", "malformed-source-evidence"),
        ("bad-run-conclusion", "malformed-source-evidence"),
        ("cancelled", "unknown-detector-result"),
    ],
)
def test_source_identity_and_result_validation_is_fail_closed(change, reason):
    """Exercise trust-boundary branches before source hashing or assessment."""
    run, job = fixture("strix-failure.json")
    call_now = NOW
    repository = "ContextualWisdomLab/naruon"
    if change == "bad-payload-type":
        run = []
    elif change == "bad-repository":
        repository = "not a repository"
    elif change == "bad-id":
        run["id"] = 0
    elif change == "missing-revision":
        run["head_sha"] = None
    elif change == "unknown-family":
        run["name"] = "Build"
        job["workflow_name"] = "Build"
        job["name"] = "unit-tests"
    elif change == "missing-job-name":
        job["name"] = None
    elif change == "bad-clock":
        call_now = None
    elif change == "bad-timestamp":
        run["updated_at"] = "not-a-time"
        job["completed_at"] = None
        run["created_at"] = None
    elif change == "missing-timestamp":
        run["updated_at"] = None
        job["completed_at"] = None
        run["created_at"] = None
    elif change == "run-success-job-failure":
        run["conclusion"] = "success"
    elif change == "bad-run-conclusion":
        run["conclusion"] = "not-a-result"
    elif change == "cancelled":
        job["conclusion"] = "cancelled"

    evidence = acquire_workflow_evidence(
        repository,
        run,
        job,
        now=call_now,  # type: ignore[arg-type]
    )
    assert evidence["assessment"]["status"] == "unknown"
    assert evidence["assessment"]["reason"] == reason


def test_optional_source_fields_and_cause_list_are_accepted():
    """Use the source API fallbacks without treating optional fields as answers."""
    run, job = fixture("strix-success.json")
    run["updated_at"] = None
    job["failure_causes"] = ["source-api-cause"]
    job["steps"].append("untrusted-step-payload")

    evidence = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", run, job, now=NOW
    )

    assert evidence["assessment"]["status"] == "clean"


def test_non_list_steps_are_malformed_source_evidence():
    """Reject a source payload that cannot be safely reduced to step metadata."""
    run, job = fixture("strix-success.json")
    job["steps"] = None

    evidence = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", run, job, now=NOW
    )

    assert evidence["assessment"]["reason"] == "malformed-source-evidence"


def test_stale_and_duplicate_artifacts_are_unknown():
    """Freshness and deduplication are part of source authority."""
    run, job = fixture("strix-failure.json")
    future_run, future_job = fixture("strix-failure.json")
    future_job["completed_at"] = "2026-08-20T02:00:00Z"
    future = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", future_run, future_job, now=NOW
    )
    delayed_run, delayed_job = fixture("strix-failure.json")
    delayed_run["updated_at"] = "2026-08-20T02:00:00Z"
    delayed_job["completed_at"] = "2026-08-20T00:00:00Z"
    delayed = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", delayed_run, delayed_job, now=NOW
    )
    stale = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon",
        run,
        job,
        now=datetime(2026, 8, 23, tzinfo=UTC),
        max_age_hours=48,
    )
    fresh = acquire_workflow_evidence("ContextualWisdomLab/naruon", run, job, now=NOW)
    duplicate = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon",
        run,
        job,
        now=NOW,
        seen_artifact_refs={fresh["source_identity"]["artifact_ref"]},
    )

    assert future["assessment"]["status"] == "unknown"
    assert future["assessment"]["reason"] == "stale-source-evidence"
    assert delayed["assessment"]["status"] == "detected"
    assert stale["assessment"]["reason"] == "stale-source-evidence"
    assert duplicate["assessment"]["reason"] == "duplicate-source-artifact"
    assert duplicate["assessment"]["status"] == "unknown"


def test_source_hash_is_derived_and_changes_with_source_content():
    """Caller assertions cannot replace the hash of the acquired source fields."""
    baseline_run, baseline_job = fixture("strix-failure.json")
    baseline = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", baseline_run, baseline_job, now=NOW
    )
    run, job = fixture("strix-failure.json")
    job["assessment"] = {"status": "clean"}
    job["source_artifact_sha256"] = "attacker-provided-hash"
    first = acquire_workflow_evidence("ContextualWisdomLab/naruon", run, job, now=NOW)

    changed = dict(job, name="changed-source-job")
    second = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", run, changed, now=NOW
    )

    assert first["source_identity"]["artifact_sha256"] != "attacker-provided-hash"
    assert (
        first["source_identity"]["artifact_sha256"]
        == baseline["source_identity"]["artifact_sha256"]
    )
    assert (
        first["source_identity"]["artifact_sha256"]
        != second["source_identity"]["artifact_sha256"]
    )
    assert first["assessment"]["status"] == "detected"


def test_source_conclusion_mutation_changes_typed_result():
    """Changing the acquired conclusion changes the result rather than an assertion field."""
    run, job = fixture("strix-failure.json")
    job["assessment"] = {"status": "clean"}
    job["conclusion"] = "success"

    evidence = acquire_workflow_evidence(
        "ContextualWisdomLab/naruon", run, job, now=NOW
    )

    assert evidence["assessment"]["status"] == "clean"
    assert evidence["assessment"]["reason"] == "security-workflow-job-success"


def test_collector_binds_source_evidence_and_issueops_renders_only_compact_proof():
    """The production collector path carries evidence through IssueOps."""
    run, job = fixture("strix-failure.json")
    run["assessment"] = {"status": "clean"}
    job["assessment"] = {"status": "clean"}
    job["source_artifact_sha256"] = "caller-asserted-digest"
    item = collector.build_source_bound_finding(
        "ContextualWisdomLab/naruon", run, job, now=NOW
    )

    assert item["source_evidence"]["assessment"]["status"] == "detected"
    summary = issueops.summary(item)
    body = issueops.issue_body(item, {collector.seen_key(item)})
    assert "Source evidence status" in summary
    assert "probe_ref" in summary
    assert "acquirer_ref" in summary
    assert item["source_evidence"]["source_identity"]["artifact_sha256"] in summary
    assert "PRIVATE_SOURCE_SECRET" not in body


def test_collector_uses_source_bound_path_for_run_collection(monkeypatch):
    """Collection attaches evidence instead of accepting metadata-only findings."""
    run, job = fixture("strix-failure.json")

    class Client:
        """Return one authenticated-source-shaped run and job."""

        def pages(self, path, params=None):
            """Return only the repository or job page requested by the collector."""
            if path == "/installation/repositories":
                return [{"full_name": "ContextualWisdomLab/naruon"}]
            if path.endswith(f"/actions/runs/{run['id']}/jobs"):
                return [job]
            if path.endswith("/actions/runs"):
                return [run]
            return []

        def request(self, method, path, data=None, params=None):
            """Keep the fake client explicit if the collector requests a run directly."""
            raise AssertionError(f"unexpected {method} {path}")

    monkeypatch.setattr(collector, "utc_now", lambda: NOW)
    findings = collector.collect_findings(
        Client(),
        Namespace(
            run_url=None,
            owner="ContextualWisdomLab",
            lookback_hours=48,
        ),
    )

    assert len(findings) == 1
    assert (
        findings[0]["source_evidence"]["source_identity"]["revision"] == run["head_sha"]
    )


def test_run_url_replay_uses_configured_freshness_window(monkeypatch):
    """Historical replay follows the explicit lookback freshness bound."""
    run, job = fixture("strix-failure.json")
    run["updated_at"] = "2026-08-18T00:00:00Z"
    job["completed_at"] = "2026-08-18T00:00:00Z"

    class Client:
        """Return one deliberately older run through the run URL path."""

        def pages(self, path, params=None):
            """Return the acquired job page."""
            if path.endswith(f"/actions/runs/{run['id']}/jobs"):
                return [job]
            return []

        def request(self, method, path, data=None, params=None):
            """Return the acquired run requested by the replay URL."""
            assert method == "GET"
            assert path.endswith(f"/actions/runs/{run['id']}")
            return run

    monkeypatch.setattr(collector, "utc_now", lambda: NOW)
    findings = collector.collect_findings(
        Client(),
        Namespace(
            run_url=f"https://github.com/ContextualWisdomLab/naruon/actions/runs/{run['id']}",
            owner="ContextualWisdomLab",
            lookback_hours=72,
        ),
    )

    assert len(findings) == 1
    assert findings[0]["source_evidence"]["assessment"]["status"] == "detected"


def test_collector_does_not_publish_inconclusive_source_evidence(monkeypatch):
    """Unknown source results never enter the security-failure issue path."""
    run, job = fixture("strix-failure.json")
    job.pop("run_id")

    class Client:
        """Return one malformed source job from the collection boundary."""

        def pages(self, path, params=None):
            """Return the repository, run, and malformed job pages."""
            if path == "/installation/repositories":
                return [{"full_name": "ContextualWisdomLab/naruon"}]
            if path.endswith(f"/actions/runs/{run['id']}/jobs"):
                return [job]
            if path.endswith("/actions/runs"):
                return [run]
            return []

    monkeypatch.setattr(collector, "utc_now", lambda: NOW)
    findings = collector.collect_findings(
        Client(),
        Namespace(run_url=None, owner="ContextualWisdomLab", lookback_hours=48),
    )

    assert findings == []


def test_control_plane_persists_source_evidence_in_scan_detail():
    """The existing normalized API envelope preserves canonical source evidence."""
    run, job = fixture("strix-failure.json")
    item = collector.build_source_bound_finding(
        "ContextualWisdomLab/naruon", run, job, now=NOW
    )
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")

    scan = add_scan(conn, org_id, [item], repo=item["repo"], commit_sha=run["head_sha"])
    detail = get_scan(conn, org_id, scan["id"])

    assert detail["findings"][0]["source_evidence"] == item["source_evidence"]
