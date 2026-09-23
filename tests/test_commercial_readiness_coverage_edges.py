"""Coverage edges for the hourly commercial-readiness selector modules."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import commercial_readiness_loop as loop


ROOT = Path(__file__).resolve().parents[1]
LOOP_PATH = ROOT / "scripts" / "ci" / "commercial_readiness_loop.py"
RECONCILE_PATH = ROOT / "scripts" / "ci" / "commercial_readiness_reconcile.py"


class _Response:
    """Context-managed HTTP response with controlled bytes and media type."""

    def __init__(self, payload: bytes, content_type: str) -> None:
        """Store one immutable response body and content type."""
        self.payload = payload
        self.headers = {"content-type": content_type}

    def __enter__(self):
        """Return this response to the urllib caller."""
        return self

    def __exit__(self, *_args: object) -> bool:
        """Propagate exceptions raised inside the response context."""
        return False

    def read(self) -> bytes:
        """Return the configured response bytes."""
        return self.payload


class _Opener:
    """Return a fixed response for one or more requests."""

    def __init__(self, response: _Response) -> None:
        """Store the response returned by every request."""
        self.response = response

    def open(self, _request: object, timeout: int) -> _Response:
        """Return the fixed response after validating the bounded timeout."""
        assert timeout == 30
        return self.response


def test_no_redirect_handler_returns_no_followup_request() -> None:
    """The credential-bearing GitHub client never follows redirect responses."""
    handler = loop.NoRedirect()

    assert handler.redirect_request(object(), object(), 302, "Found", {}, "x") is None


def test_github_client_handles_empty_and_non_json_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No-content writes and bounded text responses decode deterministically."""
    responses = iter(
        (
            _Response(b"", "application/json"),
            _Response(b"plain-text", "text/plain; charset=utf-8"),
        )
    )
    monkeypatch.setattr(
        loop.urllib.request,
        "build_opener",
        lambda *_handlers: _Opener(next(responses)),
    )

    assert loop.GitHub("token").request("POST", "/empty", {"ok": True}) is None
    assert loop.GitHub("token").request("GET", "/text") == "plain-text"


def test_repository_identity_rejects_non_owner_name_syntax() -> None:
    """GitHub path construction never accepts a caller-supplied URL or traversal."""
    with pytest.raises(ValueError, match="owner/name"):
        loop._repository_path("https://github.com/attacker/repository")


class _LabelClient:
    """Raise one controlled GitHub label-creation error."""

    def __init__(self, message: str) -> None:
        """Store the bounded error text used by the contract."""
        self.message = message

    def request(self, *_args: object, **_kwargs: object) -> None:
        """Raise the configured API error."""
        raise RuntimeError(self.message)


def test_ensure_label_tolerates_duplicate_and_rejects_other_failures() -> None:
    """Only GitHub's duplicate-label response is safe to treat as success."""
    loop._ensure_label(
        _LabelClient("422 already exists"),
        "ContextualWisdomLab/appguardrail",
        "commercial-readiness",
        "reviewed gaps",
    )

    with pytest.raises(RuntimeError, match="503 unavailable"):
        loop._ensure_label(
            _LabelClient("503 unavailable"),
            "ContextualWisdomLab/appguardrail",
            "commercial-readiness",
            "reviewed gaps",
        )


class _InvalidCreateClient:
    """Return no PRs, no issues, and an invalid issue-creation response."""

    def pages(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
        """Return empty collections for pull-request and issue inventory."""
        del params
        if path.endswith("/pulls") or path.endswith("/issues"):
            return []
        raise AssertionError(f"unexpected list path: {path}")

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Accept label creation but omit the required positive issue number."""
        del data, params
        assert method == "POST"
        if path.endswith("/labels"):
            return {}
        if path.endswith("/issues"):
            return {"number": 0}
        raise AssertionError(f"unexpected mutation path: {path}")


def test_issue_creation_without_positive_number_fails_closed() -> None:
    """Malformed GitHub creation responses never become model targets."""
    with pytest.raises(RuntimeError, match="positive issue number"):
        loop.run_loop(
            _InvalidCreateClient(),
            "ContextualWisdomLab/appguardrail",
        )


@pytest.mark.parametrize("entrypoint", [LOOP_PATH, RECONCILE_PATH])
def test_script_entrypoints_fail_closed_without_token(
    entrypoint: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both executable module guards invoke their validated CLI boundaries."""
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(entrypoint), "--repository", "ContextualWisdomLab/appguardrail"],
    )

    with pytest.raises(SystemExit, match="GH_TOKEN is required"):
        runpy.run_path(str(entrypoint), run_name="__main__")
