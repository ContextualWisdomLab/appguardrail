"""Edge-contract tests for the hourly commercial-readiness loop."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "ci"
    / "commercial_readiness_loop.py"
)


def _load_module():
    """Load the scheduled-loop module after asserting the feature exists."""
    assert MODULE_PATH.exists(), "commercial-readiness loop implementation is missing"
    spec = importlib.util.spec_from_file_location(
        "commercial_readiness_loop_edges",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeClient:
    """Small GitHub client with controlled pulls, issues, and mutations."""

    def __init__(self, *, pulls=None, issues=None):
        """Store controlled API collections and mutation calls."""
        self.pulls = list(pulls or [])
        self.issues = list(issues or [])
        self.calls: list[tuple] = []

    def pages(self, path, params=None):
        """Return controlled pull-request or issue pages."""
        self.calls.append(("pages", path, params))
        if path.endswith("/pulls"):
            return list(self.pulls)
        if path.endswith("/issues"):
            return list(self.issues)
        raise AssertionError(f"unexpected page request: {path}")

    def request(self, method, path, data=None):
        """Record a mutation and return a minimal valid response."""
        self.calls.append(("request", method, path, data))
        if method == "POST" and path.endswith("/issues"):
            return {"number": 0}
        return data


def _gap_issue(module, gap_index, *, state="open", number=41):
    """Build an issue carrying one exact commercial-gap marker."""
    gap = module.COMMERCIAL_GAPS[gap_index]
    return {
        "number": number,
        "state": state,
        "title": gap.title,
        "body": module.gap_marker(gap.id),
    }


def test_redirect_handler_and_http_error_are_fail_closed(monkeypatch) -> None:
    """Redirects and rejected API responses must not degrade into silent success."""
    module = _load_module()

    assert (
        module.NoRedirect().redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://evil.invalid",
        )
        is None
    )

    error = module.urllib.error.HTTPError(
        "https://api.github.com/rate_limit",
        403,
        "Forbidden",
        {},
        io.BytesIO(b"denied"),
    )

    class FailingOpener:
        def open(self, _request, timeout):
            assert timeout == 30
            raise error

    monkeypatch.setattr(
        module.urllib.request,
        "build_opener",
        lambda *_: FailingOpener(),
    )
    client = module.GitHub("token")

    with pytest.raises(RuntimeError, match="403 denied"):
        client.request("GET", "/rate_limit")


def test_github_client_handles_empty_text_and_paginated_json(monkeypatch) -> None:
    """API decoding and pagination must preserve every list item deterministically."""
    module = _load_module()
    responses = [
        (b"", "application/json"),
        (b"plain text", "text/plain"),
    ]

    class Response:
        def __init__(self, payload, content_type):
            self.payload = payload
            self.headers = {"content-type": content_type}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return self.payload

    class Opener:
        def open(self, request, timeout):
            assert request.full_url.startswith("https://api.github.com/")
            assert timeout == 30
            payload, content_type = responses.pop(0)
            return Response(payload, content_type)

    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *_: Opener())
    client = module.GitHub("token")

    assert client.request("POST", "/empty", {"ok": True}, {"page": 1}) is None
    assert client.request("GET", "/text") == "plain text"

    calls = []
    pages = [list(range(100)), [100]]

    def fake_request(method, path, data=None, params=None):
        calls.append((method, path, data, params))
        return pages.pop(0)

    client.request = fake_request
    assert client.pages("/items", {"state": "open"}) == list(range(101))
    assert [call[3]["page"] for call in calls] == [1, 2]
    client.request = lambda *_args, **_kwargs: {"not": "a list"}
    with pytest.raises(RuntimeError, match="non-list"):
        client.pages("/items")


def test_invalid_gap_and_repository_identities_fail_before_api_use() -> None:
    """Unreviewed identifiers must not enter issue markers or GitHub API paths."""
    module = _load_module()
    with pytest.raises(ValueError, match="lower-kebab-case"):
        module.gap_marker("Invalid Gap")
    client = FakeClient()
    with pytest.raises(ValueError, match="owner/name"):
        module.run_loop(client, "ContextualWisdomLab/appguardrail/extra")
    assert client.calls == []


def test_label_creation_tolerates_duplicate_only() -> None:
    """Existing labels are harmless, while every other mutation failure propagates."""
    module = _load_module()

    class ErrorClient:
        def __init__(self, message):
            self.message = message

        def request(self, *_args, **_kwargs):
            raise RuntimeError(self.message)

    module._ensure_label(
        ErrorClient("GitHub API failed: 422 already_exists"),
        "o/r",
        "x",
        "y",
    )
    with pytest.raises(RuntimeError, match="500"):
        module._ensure_label(
            ErrorClient("GitHub API failed: 500"),
            "o/r",
            "x",
            "y",
        )


def test_active_gap_selection_ignores_malformed_and_uses_oldest_issue() -> None:
    """Malformed automation state must be ignored and duplicate active work bounded."""
    module = _load_module()
    malformed = {"number": 1, "state": "open", "body": "ordinary issue"}
    later = _gap_issue(module, 0, state="open", number=9)
    earlier = _gap_issue(module, 0, state="open", number=3)
    pull_request_item = dict(
        _gap_issue(module, 1, state="open", number=2),
        pull_request={},
    )
    client = FakeClient(issues=[malformed, later, earlier, pull_request_item])

    result = module.run_loop(client, "ContextualWisdomLab/appguardrail")

    assert result.action == "wait-gap"
    assert result.issue_number == 3


def test_missing_created_issue_number_fails_before_jules_label() -> None:
    """The loop must not label an unknown issue when GitHub creation is incomplete."""
    module = _load_module()
    client = FakeClient()

    with pytest.raises(RuntimeError, match="positive issue number"):
        module.run_loop(client, "ContextualWisdomLab/appguardrail")
    assert not any("/issues/0/labels" in str(call) for call in client.calls)


def test_main_without_explicit_argv_uses_process_arguments(monkeypatch, capsys) -> None:
    """Direct module execution must honor the process command-line arguments."""
    module = _load_module()

    class RecordingGitHub:
        def __init__(self, token):
            assert token == "workflow-token"

    monkeypatch.setenv("GH_TOKEN", "workflow-token")
    monkeypatch.setattr(
        module.os.sys,
        "argv",
        [
            "commercial_readiness_loop.py",
            "--dry-run",
            "--repository",
            "ContextualWisdomLab/appguardrail",
        ],
    )
    monkeypatch.setattr(module, "GitHub", RecordingGitHub)
    monkeypatch.setattr(
        module,
        "run_loop",
        lambda _client, repository, dry_run: module.LoopResult(
            action=(
                "complete" if repository.endswith("appguardrail") and dry_run else "bad"
            ),
            gap_id=None,
            issue_number=None,
        ),
    )

    assert module.main() == 0
    assert json.loads(capsys.readouterr().out)["action"] == "complete"
