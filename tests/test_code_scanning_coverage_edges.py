"""Coverage-completion tests for fail-closed Code Scanning production edges."""

from __future__ import annotations

import json
import sys
import urllib.error

import pytest

from appguardrail_core import code_scanning as core
from scripts.ci import collect_code_scanning_drift as drift


def _analysis(**overrides):
    """Return one valid analysis payload with controlled overrides."""
    payload = {
        "id": 1,
        "tool": {"name": "Trivy", "guid": "trivy-guid"},
        "category": "filesystem",
        "analysis_key": ".github/workflows/security.yml:scan refs/heads/develop",
        "environment": "ubuntu-latest",
        "ref": "refs/heads/develop",
        "commit_sha": "a" * 40,
        "created_at": "2026-08-04T00:00:00Z",
        "error": "",
        "warning": "",
    }
    payload.update(overrides)
    return payload


def _identity(name: str = "trivy") -> core.AnalysisIdentity:
    """Return one stable analysis identity."""
    return core.AnalysisIdentity(
        tool_name=name,
        tool_guid=f"{name}-guid",
        category="filesystem",
        analysis_key="security:scan <ref>",
        environment="ubuntu",
    )


def _drift_record(*, head_sha: str = "b" * 40) -> drift.PullRequestDriftRecord:
    """Return one confirmed drift record for publisher edge tests."""
    return drift.PullRequestDriftRecord(
        repository="ContextualWisdomLab/demo",
        pr_number=42,
        pr_url="https://github.com/ContextualWisdomLab/demo/pull/42",
        base_ref="refs/heads/develop",
        current_ref="refs/pull/42/merge",
        head_ref="refs/heads/feature",
        head_sha=head_sha,
        merge_sha="c" * 40,
        assessment=core.DriftAssessment(
            status="drift",
            missing=(_identity(),),
            reason="missing_or_unhealthy_current_analysis",
        ),
    )


def test_core_rejects_non_string_optional_fields_and_non_object_payload() -> None:
    """Container coercion and non-object payloads must remain fail-closed."""
    with pytest.raises(ValueError, match="payload must be an object"):
        core.normalize_analysis(None)  # type: ignore[arg-type]

    payload = _analysis()
    payload["tool"] = {"name": "Trivy", "guid": ["not", "text"]}
    with pytest.raises(ValueError, match="string or null"):
        core.normalize_analysis(payload)


def test_core_rejects_naive_timestamp_and_invalid_expected_sha() -> None:
    """Timezone-free timestamps and malformed comparison SHAs are unknown evidence."""
    with pytest.raises(ValueError, match="timezone"):
        core.normalize_analysis(_analysis(created_at="2026-08-04T00:00:00"))

    snapshot = core.build_snapshot(
        [],
        scope="",
        expected_refs=(),
        expected_commit_shas=("invalid",),
    )
    assert snapshot.scope == "unknown"
    assert snapshot.status == "unknown"
    assert snapshot.reason == "invalid_expected_commit_sha"


def test_core_uses_default_incomplete_reason_and_rejects_wrong_commit() -> None:
    """Incomplete pages and same-ref stale commits must never become drift."""
    incomplete = core.build_snapshot(
        [],
        scope="current",
        expected_refs=(),
        complete=False,
    )
    stale = core.build_snapshot(
        [_analysis()],
        scope="current",
        expected_refs=("refs/heads/develop",),
        expected_commit_shas=("b" * 40,),
    )

    assert incomplete.reason == "incomplete_pagination"
    assert stale.status == "unknown"
    assert stale.reason == "no_exact_analysis_evidence"


def test_core_current_unknown_reason_is_preserved() -> None:
    """A healthy base must not mask an unknown current transport state."""
    base = core.build_snapshot(
        [_analysis()],
        scope="base",
        expected_refs=("refs/heads/develop",),
    )
    current = core.build_snapshot(
        [],
        scope="current",
        expected_refs=(),
        complete=False,
        unknown_reason="permission_denied",
    )

    assessment = core.compare_snapshots(base, current)
    assert assessment.status == "unknown"
    assert assessment.reason == "permission_denied"


def test_collector_request_classifies_url_error() -> None:
    """Network transport failures must become body-safe API errors."""
    client = drift.GitHub("token")

    class FailingOpener:
        def open(self, _request, timeout):
            assert timeout == 30
            raise urllib.error.URLError("offline")

    client.opener = FailingOpener()
    with pytest.raises(drift.GitHubAPIError) as exc_info:
        client.request("GET", "/rate_limit")
    assert exc_info.value.status == 0


def test_collector_pagination_limit_is_explicit(monkeypatch) -> None:
    """An excessive sequence must remain incomplete even when every page is a list."""
    client = drift.GitHub("token")
    monkeypatch.setattr(drift, "MAX_PAGINATION_PAGES", 2)
    client.request = lambda *_args, **_kwargs: [{}] * 100

    result = client.pages("/items")

    assert result.status == "pagination_limit"
    assert result.complete is False
    assert len(result.items) == 200


@pytest.mark.parametrize(
    ("owner", "raw", "message"),
    [
        ("../owner", "demo", "owner"),
        ("ContextualWisdomLab", "a/b/c", "repository"),
        ("ContextualWisdomLab", "ContextualWisdomLab/..", "invalid"),
        ("ContextualWisdomLab", "bad name", "invalid"),
        ("ContextualWisdomLab", "", "at least one"),
    ],
)
def test_repository_allowlist_rejects_invalid_boundaries(
    owner: str, raw: str, message: str
) -> None:
    """Traversal, invalid segments, excess slashes, and empty lists are rejected."""
    with pytest.raises(ValueError, match=message):
        drift.parse_repositories(owner, raw)


def test_pull_request_parser_rejects_every_malformed_boundary() -> None:
    """PR identity fields are mandatory before any analysis can be compared."""
    invalid_payloads = [
        None,
        {},
        {"number": True},
        {"number": 1, "base": {}, "head": None},
        {"number": 1, "base": {"ref": ""}, "head": {"ref": "x", "sha": "b" * 40}},
        {"number": 1, "base": {"ref": "develop"}, "head": {"ref": "x", "sha": "bad"}},
        {
            "number": 1,
            "base": {"ref": "develop"},
            "head": {"ref": "x", "sha": "b" * 40},
            "merge_commit_sha": "bad",
        },
    ]
    for payload in invalid_payloads:
        with pytest.raises(ValueError):
            drift._parse_pull_request(payload)


def test_collect_records_rejects_invalid_bounds_and_owner() -> None:
    """Collection must reject an unbounded run and repositories outside the owner."""
    with pytest.raises(ValueError, match="positive"):
        drift.collect_records(
            object(),
            owner="ContextualWisdomLab",
            repositories=(),
            max_pull_requests=0,
        )
    with pytest.raises(ValueError, match="owner"):
        drift.collect_records(
            object(),
            owner="ContextualWisdomLab",
            repositories=("Other/demo",),
        )


class PageClient:
    """Minimal client for collection branch coverage."""

    def __init__(self, page_result):
        """Store one pull-request page result."""
        self.page_result = page_result

    def pages(self, path, params=None):
        """Return the configured pull result and reject unexpected analysis calls."""
        del params
        if path.endswith("/pulls"):
            return self.page_result
        raise AssertionError(path)


def test_collect_records_preserves_pull_inventory_failure() -> None:
    """A repository-level PR inventory failure becomes one unknown telemetry record."""
    records = drift.collect_records(
        PageClient(drift.PageResult("permission_denied", (), False, "403")),
        owner="ContextualWisdomLab",
        repositories=("ContextualWisdomLab/demo",),
    )

    assert len(records) == 1
    assert records[0].assessment.reason == "pull_requests_permission_denied"


def test_drift_marker_and_render_reject_non_drift_records() -> None:
    """Clean or unknown telemetry can never cross the IssueOps publication boundary."""
    clean = drift.PullRequestDriftRecord(
        **{
            **_drift_record().__dict__,
            "assessment": core.DriftAssessment(status="clean"),
        }
    )
    with pytest.raises(ValueError, match="confirmed drift"):
        drift.drift_marker(clean)
    with pytest.raises(ValueError, match="confirmed drift"):
        drift.render_drift_issue(clean)


def test_marker_parser_rejects_non_object_json_and_title_rejects_bad_identity() -> None:
    """Malformed markers and incomplete issue identities cannot affect deduplication."""
    assert (
        drift.parse_drift_marker(f"{drift.MARKER_PREFIX} [] {drift.MARKER_SUFFIX}")
        == {}
    )
    invalid = _drift_record(head_sha="invalid")
    with pytest.raises(ValueError, match="exact head"):
        drift.drift_issue_title(invalid)


def test_identity_rows_has_safe_empty_fallback() -> None:
    """Unexpected empty drift evidence still renders a bounded explicit placeholder."""
    empty = drift.PullRequestDriftRecord(
        **{
            **_drift_record().__dict__,
            "assessment": core.DriftAssessment(status="drift"),
        }
    )
    assert drift._identity_rows(empty) == "- No normalized drift identity was reported."


class IssueClient:
    """Configurable issue client for index, label, and publication edge tests."""

    def __init__(self, pages_result=()):
        """Store page response and record mutations."""
        self.pages_result = pages_result
        self.calls = []
        self.create_result = None
        self.raise_message = ""

    def pages(self, path, params=None):
        """Return configured issue inventory."""
        self.calls.append(("pages", path, params))
        return self.pages_result

    def request(self, method, path, data=None):
        """Record mutations or raise a configured response."""
        self.calls.append((method, path, data))
        if self.raise_message:
            raise RuntimeError(self.raise_message)
        if method == "POST" and path.endswith("/issues"):
            return self.create_result
        return data


def test_issue_index_rejects_incomplete_and_malformed_results() -> None:
    """Issue deduplication must fail closed when target inventory is unavailable."""
    with pytest.raises(RuntimeError, match="permission_denied"):
        drift._issue_items(
            IssueClient(drift.PageResult("permission_denied", (), False)),
            "ContextualWisdomLab/appguardrail",
        )
    with pytest.raises(RuntimeError, match="malformed"):
        drift._issue_items(
            IssueClient({"not": "a list"}), "ContextualWisdomLab/appguardrail"
        )


def test_issue_index_filters_noise_and_pull_requests() -> None:
    """Only ordinary title-bearing issues are eligible for drift deduplication."""
    values = [
        "noise",
        {},
        {"title": "PR", "pull_request": {}},
        {"number": 1, "title": "Issue", "body": ""},
    ]
    assert drift._issue_items(
        IssueClient(values), "ContextualWisdomLab/appguardrail"
    ) == [values[-1]]


def test_label_creation_tolerates_duplicate_only() -> None:
    """GitHub's existing-label response is harmless while other failures propagate."""

    class LabelClient:
        """Raise one typed GitHub response for label creation."""

        def __init__(self, status: int) -> None:
            """Store the response status."""
            self.status = status

        def request(self, *_args, **_kwargs):
            """Raise the configured typed response."""
            raise drift.GitHubAPIError(self.status)

    drift._ensure_label(LabelClient(422), "ContextualWisdomLab/appguardrail", "x")
    with pytest.raises(drift.GitHubAPIError) as exc_info:
        drift._ensure_label(LabelClient(500), "ContextualWisdomLab/appguardrail", "x")
    assert exc_info.value.status == 500


def test_publish_reopens_changed_closed_issue_and_bounds_updates(monkeypatch) -> None:
    """Changed exact-head evidence reopens once, while a zero run bound mutates nothing."""
    original = _drift_record()
    changed = _drift_record()
    changed = drift.PullRequestDriftRecord(
        **{
            **changed.__dict__,
            "assessment": core.DriftAssessment(
                status="drift",
                missing=(_identity(), _identity("codeql")),
                reason="missing_or_unhealthy_current_analysis",
            ),
        }
    )
    existing = {
        "number": 7,
        "state": "closed",
        "title": drift.drift_issue_title(original),
        "body": drift.render_drift_issue(original),
    }
    client = IssueClient([existing])

    assert (
        drift.publish_records(client, "ContextualWisdomLab/appguardrail", (changed,))
        == 1
    )
    patch = next(call for call in client.calls if call[0] == "PATCH")
    assert patch[2]["state"] == "open"

    bounded = IssueClient([])
    monkeypatch.setattr(drift, "MAX_ISSUE_UPDATES_PER_RUN", 0)
    assert (
        drift.publish_records(bounded, "ContextualWisdomLab/appguardrail", (original,))
        == 0
    )


def test_publish_handles_non_object_create_response() -> None:
    """A bodyless successful create response remains bounded within the current run."""
    client = IssueClient([])
    client.create_result = None
    assert (
        drift.publish_records(
            client, "ContextualWisdomLab/appguardrail", (_drift_record(),)
        )
        == 1
    )


def test_parse_args_uses_environment_defaults(monkeypatch) -> None:
    """Scheduled execution reads all bounded inputs from reviewed environment values."""
    monkeypatch.setenv("GITHUB_REPOSITORY_OWNER", "ContextualWisdomLab")
    monkeypatch.setenv("GITHUB_REPOSITORY", "ContextualWisdomLab/appguardrail")
    monkeypatch.setenv("CODE_SCANNING_DRIFT_REPOSITORIES", "appguardrail")
    monkeypatch.setenv("CODE_SCANNING_DRIFT_MAX_PULL_REQUESTS", "17")

    args = drift.parse_args([])

    assert args.owner == "ContextualWisdomLab"
    assert args.target_repo == "ContextualWisdomLab/appguardrail"
    assert args.repositories == "appguardrail"
    assert args.max_pull_requests == 17


def test_main_without_argv_uses_process_arguments(monkeypatch, capsys) -> None:
    """Module execution honors process arguments while keeping split clients."""
    clients = []

    class Client:
        def __init__(self, token):
            self.token = token
            clients.append(self)

    monkeypatch.setenv("GH_READ_TOKEN", "read")
    monkeypatch.setenv("GH_WRITE_TOKEN", "write")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "collect_code_scanning_drift.py",
            "--owner",
            "ContextualWisdomLab",
            "--target-repo",
            "ContextualWisdomLab/appguardrail",
            "--repositories",
            "appguardrail",
        ],
    )
    monkeypatch.setattr(drift, "GitHub", Client)
    monkeypatch.setattr(drift, "collect_records", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(drift, "publish_records", lambda *_args, **_kwargs: 0)

    assert drift.main() == 0
    assert [client.token for client in clients] == ["read", "write"]
    assert json.loads(capsys.readouterr().out)["total"] == 0
