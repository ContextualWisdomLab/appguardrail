"""Workflow and CLI contracts for scheduled Code Scanning drift collection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from appguardrail_core.code_scanning import DriftAssessment
from scripts.ci import collect_code_scanning_drift as drift

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "org-security-failure-collector.yml"


def test_org_collector_grants_only_required_live_analysis_permissions() -> None:
    """The read token gains PR/Code Scanning reads while issue mutation stays isolated."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "permission-actions: read" in workflow
    assert "permission-checks: read" in workflow
    assert "permission-pull-requests: read" in workflow
    assert "permission-security-events: read" in workflow
    assert "permission-issues: write" in workflow
    assert workflow.count("permission-issues: write") == 1
    assert "repositories: appguardrail" in workflow
    assert "persist-credentials: false" in workflow
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert (
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
        in workflow
    )


def test_org_collector_runs_drift_after_existing_failure_collection() -> None:
    """One reviewed allowlist and the existing split credentials must serve both collectors."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    failure_command = "python3 -m scripts.ci.collect_org_security_failures"
    drift_command = "python3 -m scripts.ci.collect_code_scanning_drift"
    assert failure_command in workflow
    assert drift_command in workflow
    assert workflow.index(failure_command) < workflow.index(drift_command)
    assert (
        "CODE_SCANNING_DRIFT_REPOSITORIES: ${{ steps.app-config.outputs.repositories }}"
        in workflow
    )
    assert '--repositories "$CODE_SCANNING_DRIFT_REPOSITORIES"' in workflow
    assert "GH_READ_TOKEN: ${{ steps.read-app-token.outputs.token }}" in workflow
    assert "GH_WRITE_TOKEN: ${{ steps.write-app-token.outputs.token }}" in workflow
    assert (
        "secrets."
        not in workflow.split("- name: Collect Code Scanning analysis drift", 1)[1]
    )


def test_parse_args_supports_explicit_bounded_configuration() -> None:
    """The CLI must expose owner, target repository, allowlist, and a positive bound."""
    args = drift.parse_args(
        [
            "--owner",
            "ContextualWisdomLab",
            "--target-repo",
            "ContextualWisdomLab/appguardrail",
            "--repositories",
            "appguardrail,naruon",
            "--max-pull-requests",
            "25",
        ]
    )

    assert args.owner == "ContextualWisdomLab"
    assert args.target_repo == "ContextualWisdomLab/appguardrail"
    assert args.repositories == "appguardrail,naruon"
    assert args.max_pull_requests == 25


def test_main_requires_distinct_read_and_write_tokens(monkeypatch) -> None:
    """The CLI must fail closed without the two least-privilege credentials."""
    monkeypatch.delenv("GH_READ_TOKEN", raising=False)
    monkeypatch.delenv("GH_WRITE_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="both required"):
        drift.main(
            [
                "--owner",
                "ContextualWisdomLab",
                "--repositories",
                "appguardrail",
            ]
        )

    monkeypatch.setenv("GH_READ_TOKEN", "same-token")
    monkeypatch.setenv("GH_WRITE_TOKEN", "same-token")
    with pytest.raises(SystemExit, match="distinct"):
        drift.main(
            [
                "--owner",
                "ContextualWisdomLab",
                "--repositories",
                "appguardrail",
            ]
        )


def test_main_collects_with_read_client_and_publishes_with_write_client(
    monkeypatch, capsys
) -> None:
    """The entry point must preserve credential separation and emit bounded telemetry."""
    clients = []

    class RecordingGitHub:
        def __init__(self, token):
            self.token = token
            clients.append(self)

    record = drift.PullRequestDriftRecord(
        repository="ContextualWisdomLab/appguardrail",
        pr_number=863,
        pr_url="https://github.com/ContextualWisdomLab/appguardrail/pull/863",
        base_ref="refs/heads/develop",
        current_ref="refs/pull/863/merge",
        head_ref="refs/heads/feat/code-scanning-analysis-drift-862",
        head_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        merge_sha="cccccccccccccccccccccccccccccccccccccccc",
        assessment=DriftAssessment(status="unknown", reason="permission_denied"),
    )
    observed = {}

    def collect(client, *, owner, repositories, max_pull_requests):
        observed["read_token"] = client.token
        observed["owner"] = owner
        observed["repositories"] = repositories
        observed["max"] = max_pull_requests
        return (record,)

    def publish(client, target_repo, records):
        observed["write_token"] = client.token
        observed["target"] = target_repo
        observed["records"] = tuple(records)
        return 0

    monkeypatch.setenv("GH_READ_TOKEN", "read-token")
    monkeypatch.setenv("GH_WRITE_TOKEN", "write-token")
    monkeypatch.setattr(drift, "GitHub", RecordingGitHub)
    monkeypatch.setattr(drift, "collect_records", collect)
    monkeypatch.setattr(drift, "publish_records", publish)

    assert (
        drift.main(
            [
                "--owner",
                "ContextualWisdomLab",
                "--target-repo",
                "ContextualWisdomLab/appguardrail",
                "--repositories",
                "appguardrail,naruon",
                "--max-pull-requests",
                "25",
            ]
        )
        == 0
    )

    assert [client.token for client in clients] == ["read-token", "write-token"]
    assert observed == {
        "read_token": "read-token",
        "owner": "ContextualWisdomLab",
        "repositories": (
            "ContextualWisdomLab/appguardrail",
            "ContextualWisdomLab/naruon",
        ),
        "max": 25,
        "write_token": "write-token",
        "target": "ContextualWisdomLab/appguardrail",
        "records": (record,),
    }
    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "clean": 0,
        "drift": 0,
        "published": 0,
        "total": 1,
        "unknown": 1,
    }
