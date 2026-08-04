"""Contract tests for the authenticated Code Scanning drift collector."""

from __future__ import annotations

import io
import urllib.error

import pytest

from scripts.ci.collect_code_scanning_drift import (
    GitHub,
    GitHubAPIError,
    NoRedirect,
    PageResult,
    collect_records,
    parse_repositories,
)


def _analysis(
    *,
    ref: str,
    commit_sha: str,
    tool_name: str = "Trivy",
    category: str = "filesystem",
    analysis_id: int = 1,
    error: str = "",
) -> dict:
    """Return a complete analysis payload for collector integration tests."""
    return {
        "id": analysis_id,
        "tool": {"name": tool_name, "guid": f"{tool_name.casefold()}-guid"},
        "category": category,
        "analysis_key": ".github/workflows/security.yml:scan <ref>",
        "environment": "ubuntu-latest",
        "ref": ref,
        "commit_sha": commit_sha,
        "created_at": f"2026-08-04T00:00:{analysis_id:02d}Z",
        "error": error,
        "warning": "",
    }


def _pull(number: int = 42) -> dict:
    """Return one open pull request payload with exact head and merge evidence."""
    return {
        "number": number,
        "html_url": f"https://github.com/ContextualWisdomLab/demo/pull/{number}",
        "base": {"ref": "develop"},
        "head": {
            "ref": "feature/live-drift",
            "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
        "merge_commit_sha": "cccccccccccccccccccccccccccccccccccccccc",
    }


def test_no_redirect_rejects_authenticated_redirects() -> None:
    """The live collector token must never be forwarded to another origin."""
    assert (
        NoRedirect().redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://attacker.invalid/",
        )
        is None
    )


def test_github_client_pins_public_api_origin() -> None:
    """Callers cannot replace the reviewed GitHub API origin."""
    GitHub("token")
    with pytest.raises(ValueError, match="api.github.com"):
        GitHub("token", "https://attacker.invalid")


def test_github_pages_collects_every_page_and_validates_list_shape() -> None:
    """Pagination must read every item and fail closed on malformed payloads."""
    client = GitHub("token")
    calls: list[dict] = []
    pages = [list(range(100)), [100]]

    def request(_method, _path, _data=None, params=None):
        calls.append(dict(params or {}))
        return pages.pop(0)

    client.request = request
    result = client.pages("/items", {"state": "open"})

    assert result == PageResult("ok", tuple(range(101)), True, "")
    assert [call["page"] for call in calls] == [1, 2]
    assert all(call["per_page"] == 100 for call in calls)

    client.request = lambda *_args, **_kwargs: {"not": "a list"}
    malformed = client.pages("/items")
    assert malformed.status == "malformed_payload"
    assert malformed.complete is False


def test_github_pages_classifies_permission_service_and_api_failures() -> None:
    """GitHub response classes must remain explicit unknown evidence states."""
    client = GitHub("token")
    expected = {
        403: "permission_denied",
        404: "not_found",
        503: "service_unavailable",
        500: "api_error",
    }
    for status, state in expected.items():
        client.request = lambda *_args, _status=status, **_kwargs: (_ for _ in ()).throw(
            GitHubAPIError(_status, "denied")
        )
        result = client.pages("/items")
        assert result.status == state
        assert result.complete is False


def test_github_request_redacts_error_body_from_exception() -> None:
    """HTTP error text must expose status without echoing a potentially secret body."""
    client = GitHub("token")
    error = urllib.error.HTTPError(
        "https://api.github.com/items",
        403,
        "Forbidden",
        {},
        io.BytesIO(b'authorization: Bearer secret-value'),
    )

    class FailingOpener:
        def open(self, _request, timeout):
            assert timeout == 30
            raise error

    client.opener = FailingOpener()
    with pytest.raises(GitHubAPIError, match="403") as exc_info:
        client.request("GET", "/items")
    assert "secret-value" not in str(exc_info.value)


def test_parse_repositories_normalizes_reviewed_allowlist() -> None:
    """Only unique repositories under the configured owner may be queried."""
    assert parse_repositories(
        "ContextualWisdomLab", "appguardrail, naruon\nfast-mlsirm"
    ) == (
        "ContextualWisdomLab/appguardrail",
        "ContextualWisdomLab/naruon",
        "ContextualWisdomLab/fast-mlsirm",
    )

    with pytest.raises(ValueError, match="duplicate"):
        parse_repositories("ContextualWisdomLab", "appguardrail,APPGUARDRAIL")
    with pytest.raises(ValueError, match="repository"):
        parse_repositories("ContextualWisdomLab", "../escape")
    with pytest.raises(ValueError, match="owner"):
        parse_repositories("ContextualWisdomLab", "other/repository")


class FakeClient:
    """Path-aware page client for deterministic collection tests."""

    def __init__(self, responses: dict[tuple[str, tuple[tuple[str, object], ...]], PageResult]):
        """Store endpoint responses and record every paginated request."""
        self.responses = responses
        self.calls: list[tuple[str, dict[str, object]]] = []

    def pages(self, path: str, params: dict | None = None) -> PageResult:
        """Return one response keyed by path and exact query parameters."""
        normalized = dict(params or {})
        self.calls.append((path, normalized))
        key = (path, tuple(sorted(normalized.items())))
        return self.responses[key]


def _responses(
    *,
    current: PageResult,
    base: PageResult | None = None,
    pulls: PageResult | None = None,
) -> dict[tuple[str, tuple[tuple[str, object], ...]], PageResult]:
    """Build exact API responses for one allowlisted repository."""
    repository = "ContextualWisdomLab/demo"
    base_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    return {
        (
            f"/repos/{repository}/pulls",
            tuple(
                sorted(
                    {
                        "state": "open",
                        "sort": "updated",
                        "direction": "desc",
                    }.items()
                )
            ),
        ): pulls or PageResult("ok", (_pull(),), True, ""),
        (
            f"/repos/{repository}/code-scanning/analyses",
            tuple(
                sorted(
                    {
                        "ref": "refs/heads/develop",
                        "sort": "created",
                        "direction": "desc",
                    }.items()
                )
            ),
        ): base
        or PageResult(
            "ok",
            (
                _analysis(
                    ref="refs/heads/develop",
                    commit_sha=base_sha,
                ),
            ),
            True,
            "",
        ),
        (
            f"/repos/{repository}/code-scanning/analyses",
            tuple(
                sorted(
                    {
                        "pr": 42,
                        "sort": "created",
                        "direction": "desc",
                    }.items()
                )
            ),
        ): current,
    }


def test_collect_records_compares_base_and_exact_pull_request_evidence() -> None:
    """The collector must use documented base-ref and pull-request API filters."""
    current = PageResult(
        "ok",
        (
            _analysis(
                ref="refs/pull/42/merge",
                commit_sha="cccccccccccccccccccccccccccccccccccccccc",
                analysis_id=2,
            ),
        ),
        True,
        "",
    )
    client = FakeClient(_responses(current=current))

    records = collect_records(
        client,
        owner="ContextualWisdomLab",
        repositories=("ContextualWisdomLab/demo",),
    )

    assert len(records) == 1
    assert records[0].assessment.status == "clean"
    assert records[0].base_ref == "refs/heads/develop"
    assert records[0].current_ref == "refs/pull/42/merge"
    assert records[0].head_sha == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert records[0].merge_sha == "cccccccccccccccccccccccccccccccccccccccc"


def test_collect_records_reports_confirmed_drift_for_complete_empty_current_set() -> None:
    """A complete empty PR analysis set is confirmed drift when base evidence exists."""
    client = FakeClient(_responses(current=PageResult("ok", (), True, "")))

    records = collect_records(
        client,
        owner="ContextualWisdomLab",
        repositories=("ContextualWisdomLab/demo",),
    )

    assert records[0].assessment.status == "drift"
    assert tuple(item.tool_name for item in records[0].assessment.missing) == ("trivy",)


def test_collect_records_preserves_unknown_permission_state_without_drift() -> None:
    """Partial permissions must not publish a false missing-configuration result."""
    client = FakeClient(
        _responses(current=PageResult("permission_denied", (), False, "403"))
    )

    records = collect_records(
        client,
        owner="ContextualWisdomLab",
        repositories=("ContextualWisdomLab/demo",),
    )

    assert records[0].assessment.status == "unknown"
    assert records[0].assessment.reason == "permission_denied"


def test_collect_records_accepts_exact_head_analysis_and_bounds_pull_requests() -> None:
    """Head-ref analyses are valid exact evidence and collection is globally bounded."""
    first = _pull(42)
    second = _pull(43)
    pulls = PageResult("ok", (first, second), True, "")
    current = PageResult(
        "ok",
        (
            _analysis(
                ref="refs/heads/feature/live-drift",
                commit_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                analysis_id=2,
            ),
        ),
        True,
        "",
    )
    client = FakeClient(_responses(current=current, pulls=pulls))

    records = collect_records(
        client,
        owner="ContextualWisdomLab",
        repositories=("ContextualWisdomLab/demo",),
        max_pull_requests=1,
    )

    assert len(records) == 1
    assert records[0].pr_number == 42
    assert records[0].assessment.status == "clean"


def test_collect_records_returns_unknown_for_malformed_pull_request_payload() -> None:
    """Malformed pull request metadata must remain an explicit unknown record."""
    pulls = PageResult("ok", ({"number": 42},), True, "")
    client = FakeClient(
        _responses(current=PageResult("ok", (), True, ""), pulls=pulls)
    )

    records = collect_records(
        client,
        owner="ContextualWisdomLab",
        repositories=("ContextualWisdomLab/demo",),
    )

    assert len(records) == 1
    assert records[0].assessment.status == "unknown"
    assert records[0].assessment.reason == "malformed_pull_request"
