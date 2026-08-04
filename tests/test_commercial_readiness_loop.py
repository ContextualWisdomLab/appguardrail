"""Contract tests for the hourly commercial-readiness development loop."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ci" / "commercial_readiness_loop.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "commercial-readiness-loop.yml"


def _load_module():
    """Load the scheduled-loop module after asserting the feature exists."""
    assert MODULE_PATH.exists(), "commercial-readiness loop implementation is missing"
    spec = importlib.util.spec_from_file_location("commercial_readiness_loop", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeClient:
    """Small in-memory GitHub client used to verify orchestration behavior."""

    def __init__(self, *, pulls=None, issues=None):
        """Store controlled GitHub API list results and mutation history."""
        self.pulls = list(pulls or [])
        self.issues = list(issues or [])
        self.calls: list[tuple] = []
        self.next_issue_number = 901

    def pages(self, path, params=None):
        """Return the configured pull-request or issue collection."""
        self.calls.append(("pages", path, params))
        if path.endswith("/pulls"):
            return list(self.pulls)
        if path.endswith("/issues"):
            return list(self.issues)
        raise AssertionError(f"unexpected page request: {path}")

    def request(self, method, path, data=None):
        """Record mutations and return normalized label or issue responses."""
        self.calls.append(("request", method, path, data))
        if method == "POST" and path.endswith("/labels") and "/issues/" not in path:
            return data
        if method == "POST" and path.endswith("/issues"):
            issue = {
                "number": self.next_issue_number,
                "state": "open",
                "title": data["title"],
                "body": data["body"],
                "labels": data.get("labels", []),
            }
            self.next_issue_number += 1
            self.issues.append(issue)
            return issue
        raise AssertionError(f"unexpected mutation: {method} {path}")


def _gap_issue(module, gap_index, *, state="open", number=41):
    """Build an issue carrying one exact commercial-gap marker."""
    gap = module.COMMERCIAL_GAPS[gap_index]
    return {
        "number": number,
        "state": state,
        "title": gap.title,
        "body": module.gap_marker(gap.id),
    }


def test_hourly_workflow_is_default_branch_only_and_secret_bounded() -> None:
    """The scheduler may write only from reviewed default-branch source."""
    assert WORKFLOW_PATH.exists(), "hourly commercial-readiness workflow is missing"
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    lowered = workflow.lower()

    assert 'cron: "17 * * * *"' in workflow
    assert "pull_request:" not in workflow
    assert "pull_request_target:" not in workflow
    assert "workflow_dispatch:" in workflow
    assert "contents: write" in workflow
    assert "issues: write" in workflow
    assert "pull-requests: write" in workflow
    assert "persist-credentials: false" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "python3 -m scripts.ci.commercial_readiness_loop" in workflow
    assert "secrets.NVIDIA_NIM_API_KEY" in workflow
    assert "NVIDIA_API_KEY" in workflow
    assert "anomalyco/opencode/github@77fc88c8ade8e5a620ebbe1197f3a572d29ae91a" in workflow
    assert "jules" not in lowered
    assert "copilot" not in lowered
    assert "PR_REVIEW_MERGE_TOKEN" not in workflow
    assert "OPENCODE_APPROVE_TOKEN" not in workflow


def test_open_pr_queue_blocks_new_opencode_dispatch() -> None:
    """A live PR must be reviewed and merged before another product gap starts."""
    module = _load_module()
    client = FakeClient(pulls=[{"number": 853}, {"number": 855}])

    result = module.run_loop(client, "ContextualWisdomLab/appguardrail")

    assert result.action == "wait-prs"
    assert result.pull_requests == (853, 855)
    assert not [call for call in client.calls if call[:2] == ("request", "POST")]


def test_no_open_pr_dispatches_first_unfinished_gap_for_opencode() -> None:
    """The first unfinished buyer-visible gap becomes one OpenCode work item."""
    module = _load_module()
    client = FakeClient()

    result = module.run_loop(client, "ContextualWisdomLab/appguardrail")

    assert result.action == "dispatch-gap"
    assert result.gap_id == module.COMMERCIAL_GAPS[0].id
    assert result.issue_number == 901
    created = next(
        call
        for call in client.calls
        if call[:3]
        == (
            "request",
            "POST",
            "/repos/ContextualWisdomLab/appguardrail/issues",
        )
    )
    assert module.gap_marker(result.gap_id) in created[3]["body"]
    assert created[3]["labels"] == [module.COMMERCIAL_LABEL]
    issue_mutations = [
        call
        for call in client.calls
        if call[:2] == ("request", "POST") and "/issues/901/" in call[2]
    ]
    assert issue_mutations == []


def test_open_gap_prevents_duplicate_dispatch() -> None:
    """An unfinished issue must remain the sole active development slice."""
    module = _load_module()
    active = _gap_issue(module, 0)
    client = FakeClient(issues=[active])

    result = module.run_loop(client, "ContextualWisdomLab/appguardrail")

    assert result.action == "wait-gap"
    assert result.gap_id == module.COMMERCIAL_GAPS[0].id
    assert result.issue_number == active["number"]
    assert not [call for call in client.calls if call[:2] == ("request", "POST")]


def test_closed_gap_advances_by_priority_not_issue_number() -> None:
    """A completed gap advances to the next declared buyer-value priority."""
    module = _load_module()
    completed = _gap_issue(module, 0, state="closed", number=999)
    client = FakeClient(issues=[completed])

    result = module.run_loop(client, "ContextualWisdomLab/appguardrail")

    assert result.action == "dispatch-gap"
    assert result.gap_id == module.COMMERCIAL_GAPS[1].id


def test_all_declared_gaps_complete_without_spawning_placeholder_work() -> None:
    """The loop stops cleanly when its reviewed backlog has been exhausted."""
    module = _load_module()
    issues = [
        _gap_issue(module, index, state="closed", number=100 + index)
        for index in range(len(module.COMMERCIAL_GAPS))
    ]
    client = FakeClient(issues=issues)

    result = module.run_loop(client, "ContextualWisdomLab/appguardrail")

    assert result.action == "complete"
    assert result.gap_id is None
    assert not [call for call in client.calls if call[:2] == ("request", "POST")]


def test_gap_marker_rejects_unknown_or_embedded_identity() -> None:
    """Only a reviewed exact gap id may influence autonomous dispatch state."""
    module = _load_module()

    assert module.parse_gap_marker(module.gap_marker(module.COMMERCIAL_GAPS[0].id)) == (
        module.COMMERCIAL_GAPS[0].id
    )
    assert module.parse_gap_marker("prefix " + module.gap_marker("unknown-gap")) is None
    assert module.parse_gap_marker(
        "<!-- appguardrail-commercial-gap: unknown-gap -->"
    ) is None
    assert module.parse_gap_marker(None) is None


def test_gap_issue_contract_requires_opencode_tdd_evidence_and_modularity() -> None:
    """Every autonomous task carries the repository's commercial quality gates."""
    module = _load_module()
    gap = module.COMMERCIAL_GAPS[0]

    body = module.render_gap_issue(gap)

    assert gap.objective in body
    assert all(item in body for item in gap.acceptance)
    assert "OpenCode Agent" in body
    assert "NVIDIA_NIM_API_KEY" in body
    assert "test first" in body.lower()
    assert "100%" in body
    assert "CHANGELOG" in body
    assert "develop" in body
    assert "MSA" in body
    assert "APA 7th" in body
    assert "must not merge" in body.lower()
    assert module.gap_marker(gap.id) in body


def test_dry_run_reports_dispatch_without_mutating_github() -> None:
    """Dry-run validation exercises selection without writing labels or issues."""
    module = _load_module()
    client = FakeClient()

    result = module.run_loop(
        client,
        "ContextualWisdomLab/appguardrail",
        dry_run=True,
    )

    assert result.action == "dispatch-gap"
    assert result.issue_number is None
    assert not [call for call in client.calls if call[:2] == ("request", "POST")]


def test_github_client_pins_origin_and_rejects_redirects(monkeypatch) -> None:
    """The hourly write credential never follows a caller-selected origin."""
    module = _load_module()
    observed = {}

    class Response:
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"ok": true}'

    class Opener:
        def open(self, request, timeout):
            observed["url"] = request.full_url
            observed["authorization"] = request.get_header("Authorization")
            observed["timeout"] = timeout
            return Response()

    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *_: Opener())
    client = module.GitHub("sensitive-token")

    assert client.request("GET", "/rate_limit") == {"ok": True}
    assert observed == {
        "url": "https://api.github.com/rate_limit",
        "authorization": "Bearer sensitive-token",
        "timeout": 30,
    }
    with pytest.raises(ValueError, match="api.github.com"):
        module.GitHub("token", "https://attacker.invalid")
    with pytest.raises(ValueError, match="path must start"):
        client.request("GET", "https://attacker.invalid/")


def test_cli_main_requires_token_and_emits_machine_result(monkeypatch, capsys) -> None:
    """The workflow entry point fails closed and exposes a stable JSON result."""
    module = _load_module()

    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="GH_TOKEN is required"):
        module.main(["--repository", "ContextualWisdomLab/appguardrail"])

    class RecordingGitHub:
        def __init__(self, token):
            assert token == "workflow-token"

    expected = module.LoopResult(
        action="wait-prs",
        gap_id=None,
        issue_number=None,
        pull_requests=(7,),
    )
    monkeypatch.setenv("GH_TOKEN", "workflow-token")
    monkeypatch.setattr(module, "GitHub", RecordingGitHub)
    monkeypatch.setattr(module, "run_loop", lambda *_args, **_kwargs: expected)

    assert module.main(["--repository", "ContextualWisdomLab/appguardrail"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "action": "wait-prs",
        "gap_id": None,
        "issue_number": None,
        "pull_requests": [7],
    }


def test_parse_args_uses_repository_environment(monkeypatch) -> None:
    """Scheduled runs use the exact repository identity supplied by GitHub."""
    module = _load_module()
    monkeypatch.setenv("GITHUB_REPOSITORY", "ContextualWisdomLab/appguardrail")

    args = module.parse_args(["--dry-run"])

    assert args == SimpleNamespace(
        repository="ContextualWisdomLab/appguardrail",
        dry_run=True,
    )
