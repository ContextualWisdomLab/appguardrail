#!/usr/bin/env python3
"""Collect and publish fail-closed GitHub Code Scanning analysis drift evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

from appguardrail_core.code_scanning import (
    AnalysisIdentity,
    AnalysisSnapshot,
    DriftAssessment,
    build_snapshot,
    compare_snapshots,
)
from scripts.ci.commercial_readiness_loop import (
    GitHub as _BaseGitHub,
    NoRedirect as _BaseNoRedirect,
)


DEFAULT_MAX_PULL_REQUESTS = 100
MAX_PAGINATION_PAGES = 100
MAX_ISSUE_BODY_CHARS = 60_000
MAX_ISSUE_UPDATES_PER_RUN = 100
DRIFT_LABEL = "code-scanning-drift"
SECURITY_LABEL = "security-ci"
MARKER_PREFIX = "<!-- appguardrail-code-scanning-drift:"
MARKER_SUFFIX = "-->"
_REPOSITORY_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


class NoRedirect(_BaseNoRedirect):
    """Public collector redirect guard that rejects every authenticated redirect."""


class GitHubAPIError(RuntimeError):
    """Represent one classified GitHub response without exposing response bodies."""

    def __init__(self, status: int, detail: str = "") -> None:
        """Store the status while keeping untrusted response detail out of logs."""
        del detail
        self.status = int(status)
        super().__init__(f"GitHub API request failed with status {self.status}")


@dataclass(frozen=True)
class PageResult:
    """Complete page collection or an explicit fail-closed transport state."""

    status: str
    items: tuple[Any, ...]
    complete: bool
    detail: str = ""


@dataclass(frozen=True)
class PullRequestDriftRecord:
    """Live analysis comparison evidence for one exact pull request head."""

    repository: str
    pr_number: int
    pr_url: str
    base_ref: str
    current_ref: str
    head_ref: str
    head_sha: str
    merge_sha: str
    assessment: DriftAssessment


class GitHub(_BaseGitHub):
    """GitHub client that converts transport failures into body-safe status errors."""

    def __init__(self, token: str, api: str = "https://api.github.com") -> None:
        """Create a fixed-origin client using the collector's public redirect guard."""
        super().__init__(token, api)
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Delegate the fixed-origin request while suppressing response-body details."""
        try:
            return super().request(method, path, data=data, params=params)
        except RuntimeError as exc:
            cause = exc.__cause__
            status = cause.code if isinstance(cause, urllib.error.HTTPError) else 0
            raise GitHubAPIError(status) from exc
        except urllib.error.URLError as exc:
            raise GitHubAPIError(0) from exc

    def pages(
        self, path: str, params: dict[str, Any] | None = None
    ) -> PageResult:
        """Read every bounded list page and classify incomplete evidence explicitly."""
        items: list[Any] = []
        for page in range(1, MAX_PAGINATION_PAGES + 1):
            page_params = dict(params or {}, per_page=100, page=page)
            try:
                chunk = self.request("GET", path, params=page_params)
            except json.JSONDecodeError:
                return PageResult(
                    "malformed_payload", tuple(items), False, "invalid-json"
                )
            except GitHubAPIError as exc:
                status = {
                    403: "permission_denied",
                    404: "not_found",
                    503: "service_unavailable",
                }.get(exc.status, "api_error")
                return PageResult(status, tuple(items), False, str(exc.status))
            if not isinstance(chunk, list):
                return PageResult("malformed_payload", tuple(items), False, "non-list")
            items.extend(chunk)
            if len(chunk) < 100:
                return PageResult("ok", tuple(items), True, "")
        return PageResult(
            "pagination_limit",
            tuple(items),
            False,
            str(MAX_PAGINATION_PAGES),
        )


def _valid_segment(value: str) -> bool:
    """Return whether a repository segment is descriptive and traversal-safe."""
    return bool(_REPOSITORY_SEGMENT_RE.fullmatch(value)) and value not in {".", ".."}


def parse_repositories(owner: str, raw: str) -> tuple[str, ...]:
    """Normalize a reviewed repository allowlist under one exact owner."""
    normalized_owner = str(owner or "").strip()
    if not _valid_segment(normalized_owner):
        raise ValueError("owner must be one valid GitHub organization segment")
    repositories: list[str] = []
    seen: set[str] = set()
    for entry in (item.strip() for item in re.split(r"[,\n]", str(raw or ""))):
        if not entry:
            continue
        if entry.count("/") > 1:
            raise ValueError("repository must use name or exact owner/name syntax")
        if "/" in entry:
            entry_owner, repository = entry.split("/", 1)
            if not _valid_segment(entry_owner) or not _valid_segment(repository):
                raise ValueError("repository contains an invalid path segment")
            if entry_owner != normalized_owner:
                raise ValueError("repository owner must match the configured owner")
        else:
            repository = entry
            if not _valid_segment(repository):
                raise ValueError("repository contains an invalid path segment")
        full_name = f"{normalized_owner}/{repository}"
        key = full_name.casefold()
        if key in seen:
            raise ValueError(f"duplicate repository allowlist entry: {full_name}")
        seen.add(key)
        repositories.append(full_name)
    if not repositories:
        raise ValueError("repository allowlist must contain at least one entry")
    return tuple(repositories)


def _snapshot_from_result(
    result: PageResult,
    *,
    scope: str,
    expected_refs: Iterable[str],
    expected_commit_shas: Iterable[str] = (),
) -> AnalysisSnapshot:
    """Build a core snapshot only from completely paginated GitHub evidence."""
    if result.status != "ok" or not result.complete:
        return build_snapshot(
            (),
            scope=scope,
            expected_refs=(),
            complete=False,
            unknown_reason=result.status,
        )
    return build_snapshot(
        result.items,
        scope=scope,
        expected_refs=expected_refs,
        expected_commit_shas=expected_commit_shas,
    )


def _unknown_record(
    repository: str,
    reason: str,
    *,
    pr_number: int = 0,
    pr_url: str = "",
) -> PullRequestDriftRecord:
    """Return a non-publishable record for malformed or unavailable evidence."""
    return PullRequestDriftRecord(
        repository=repository,
        pr_number=pr_number,
        pr_url=pr_url,
        base_ref="",
        current_ref=f"refs/pull/{pr_number}/merge" if pr_number > 0 else "",
        head_ref="",
        head_sha="",
        merge_sha="",
        assessment=DriftAssessment(status="unknown", reason=reason),
    )


def _parse_pull_request(payload: Any) -> tuple[int, str, str, str, str, str]:
    """Validate exact pull request metadata required for comparison."""
    if not isinstance(payload, dict):
        raise ValueError("pull request must be an object")
    number = payload.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        raise ValueError("pull request number must be positive")
    base = payload.get("base")
    head = payload.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise ValueError("pull request base and head metadata are required")
    base_name = str(base.get("ref") or "").strip()
    head_name = str(head.get("ref") or "").strip()
    head_sha = str(head.get("sha") or "").strip().lower()
    merge_sha = str(payload.get("merge_commit_sha") or "").strip().lower()
    if not base_name or not head_name or not _COMMIT_SHA_RE.fullmatch(head_sha):
        raise ValueError("pull request branch and head evidence is malformed")
    if merge_sha and not _COMMIT_SHA_RE.fullmatch(merge_sha):
        raise ValueError("pull request merge SHA is malformed")
    return (
        number,
        str(payload.get("html_url") or "").strip(),
        base_name,
        head_name,
        head_sha,
        merge_sha,
    )


def collect_records(
    client: Any,
    *,
    owner: str,
    repositories: Iterable[str],
    max_pull_requests: int = DEFAULT_MAX_PULL_REQUESTS,
) -> tuple[PullRequestDriftRecord, ...]:
    """Compare base and exact-current analysis evidence for bounded open PRs."""
    if max_pull_requests <= 0:
        raise ValueError("max_pull_requests must be positive")
    normalized_owner = str(owner or "").strip()
    records: list[PullRequestDriftRecord] = []
    processed = 0
    for repository in repositories:
        if processed >= max_pull_requests:
            break
        if not isinstance(repository, str) or not repository.startswith(
            f"{normalized_owner}/"
        ):
            raise ValueError("repository owner must match the configured owner")
        pulls = client.pages(
            f"/repos/{repository}/pulls",
            {"state": "open", "sort": "updated", "direction": "desc"},
        )
        if pulls.status != "ok" or not pulls.complete:
            records.append(_unknown_record(repository, f"pull_requests_{pulls.status}"))
            continue
        for pull in pulls.items:
            if processed >= max_pull_requests:
                break
            processed += 1
            raw_number = pull.get("number") if isinstance(pull, dict) else 0
            safe_number = (
                raw_number
                if isinstance(raw_number, int)
                and not isinstance(raw_number, bool)
                and raw_number > 0
                else 0
            )
            safe_url = str(pull.get("html_url") or "") if isinstance(pull, dict) else ""
            try:
                number, pr_url, base_name, head_name, head_sha, merge_sha = (
                    _parse_pull_request(pull)
                )
            except (TypeError, ValueError):
                records.append(
                    _unknown_record(
                        repository,
                        "malformed_pull_request",
                        pr_number=safe_number,
                        pr_url=safe_url,
                    )
                )
                continue

            base_ref = f"refs/heads/{base_name}"
            current_ref = f"refs/pull/{number}/merge"
            head_ref = f"refs/heads/{head_name}"
            base_result = client.pages(
                f"/repos/{repository}/code-scanning/analyses",
                {"ref": base_ref, "sort": "created", "direction": "desc"},
            )
            current_result = client.pages(
                f"/repos/{repository}/code-scanning/analyses",
                {"pr": number, "sort": "created", "direction": "desc"},
            )
            base_snapshot = _snapshot_from_result(
                base_result,
                scope="base",
                expected_refs=(base_ref,),
            )
            current_snapshot = _snapshot_from_result(
                current_result,
                scope="current",
                expected_refs=(current_ref, head_ref),
                expected_commit_shas=tuple(
                    sha
                    for sha in (head_sha, merge_sha)
                    if _COMMIT_SHA_RE.fullmatch(sha)
                ),
            )
            records.append(
                PullRequestDriftRecord(
                    repository=repository,
                    pr_number=number,
                    pr_url=pr_url,
                    base_ref=base_ref,
                    current_ref=current_ref,
                    head_ref=head_ref,
                    head_sha=head_sha,
                    merge_sha=merge_sha,
                    assessment=compare_snapshots(base_snapshot, current_snapshot),
                )
            )
    return tuple(records)


def _identity_text(identity: AnalysisIdentity) -> str:
    """Return one deterministic, bounded identity string for markers and reports."""
    return " | ".join(
        (
            identity.tool_name,
            identity.tool_guid or "no-guid",
            identity.category,
            identity.analysis_key or "no-analysis-key",
            identity.environment or "no-environment",
        )
    )


def _evidence_items(record: PullRequestDriftRecord) -> list[str]:
    """Return sorted missing and errored identity evidence for one drift state."""
    items = [
        f"missing:{_identity_text(identity)}"
        for identity in record.assessment.missing
    ]
    items.extend(
        f"errored:{_identity_text(evidence.identity)}:{evidence.error}"
        for evidence in record.assessment.errored
    )
    return sorted(items)


def drift_marker(record: PullRequestDriftRecord) -> str:
    """Build the hidden exact-head marker used to deduplicate drift updates."""
    if record.assessment.status != "drift":
        raise ValueError("only confirmed drift records have IssueOps markers")
    identities = _evidence_items(record)
    canonical = json.dumps(identities, ensure_ascii=True, separators=(",", ":"))
    payload = {
        "evidence_key": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "head_sha": record.head_sha,
        "identities": identities,
        "pr": record.pr_number,
        "repo": record.repository,
    }
    return (
        f"{MARKER_PREFIX} "
        f"{json.dumps(payload, sort_keys=True, separators=(',', ':'))} "
        f"{MARKER_SUFFIX}"
    )


def parse_drift_marker(body: str | None) -> dict[str, Any]:
    """Parse one hidden drift marker, returning an empty object when invalid."""
    text = body or ""
    start = text.find(MARKER_PREFIX)
    end = text.find(MARKER_SUFFIX, start + len(MARKER_PREFIX))
    if start == -1 or end == -1:
        return {}
    try:
        payload = json.loads(text[start + len(MARKER_PREFIX) : end].strip())
    except (json.JSONDecodeError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def drift_issue_title(record: PullRequestDriftRecord) -> str:
    """Return a stable issue title scoped to one repository, PR, and exact head."""
    if record.pr_number <= 0 or not _COMMIT_SHA_RE.fullmatch(record.head_sha):
        raise ValueError("drift issue identity requires a positive PR and exact head SHA")
    return (
        f"[code-scanning-drift] {record.repository}"
        f"#{record.pr_number}@{record.head_sha[:12]}"
    )


def _code(value: str) -> str:
    """Return bounded single-line Markdown code text without fence injection."""
    return str(value or "").replace("`", "'").replace("\r", " ").replace("\n", " ")


def _identity_rows(record: PullRequestDriftRecord) -> str:
    """Render missing and errored analysis identities as auditable Markdown rows."""
    rows = [
        f"- Missing: `{_code(_identity_text(identity))}`"
        for identity in record.assessment.missing
    ]
    rows.extend(
        "- Errored: "
        f"`{_code(_identity_text(evidence.identity))}` — "
        f"`{_code(evidence.error)}`"
        for evidence in record.assessment.errored
    )
    return "\n".join(rows) or "- No normalized drift identity was reported."


def render_drift_issue(record: PullRequestDriftRecord) -> str:
    """Render one bounded buyer-auditable issue for confirmed live analysis drift."""
    if record.assessment.status != "drift":
        raise ValueError("only confirmed drift records can render drift issues")
    body = "\n\n".join(
        (
            drift_marker(record),
            "## Live Code Scanning analysis drift\n\n"
            "This issue is generated from **live GitHub Code Scanning analysis state** "
            "and is **not inferred from repository workflow text**. It is intentionally "
            "distinct from the repository-local "
            "`github-actions-sarif-missing-pull-request-trigger` heuristic.",
            "## Exact evidence boundary\n\n"
            f"- Repository: `{_code(record.repository)}`\n"
            f"- Pull request: {record.pr_url or f'#{record.pr_number}'}\n"
            f"- Base ref: `{_code(record.base_ref)}`\n"
            f"- Current merge ref: `{_code(record.current_ref)}`\n"
            f"- Current head ref: `{_code(record.head_ref)}`\n"
            f"- Head SHA: `{_code(record.head_sha)}`\n"
            f"- Merge SHA: `{_code(record.merge_sha or 'not reported')}`",
            f"## Missing or unhealthy analysis identities\n\n{_identity_rows(record)}",
            "## Required remediation\n\n"
            "1. Open the exact pull-request head and its Code Scanning analyses.\n"
            "2. Restore the missing tool/category or fix the errored SARIF analysis.\n"
            "3. Keep tool, category, matrix identity, and SARIF upload configuration "
            "stable between the base branch and pull-request run.\n"
            "4. Rerun analysis for the same exact head and verify this live-state drift "
            "is absent before merging.",
        )
    )
    if len(body) > MAX_ISSUE_BODY_CHARS:
        raise ValueError("drift issue exceeds the bounded GitHub issue body limit")
    return body


def _issue_items(client: Any, target_repo: str) -> list[dict[str, Any]]:
    """Read dedicated drift issues from clients returning lists or PageResult values."""
    result = client.pages(
        f"/repos/{target_repo}/issues",
        {"state": "all", "labels": DRIFT_LABEL},
    )
    if isinstance(result, PageResult):
        if result.status != "ok" or not result.complete:
            raise RuntimeError(f"unable to index drift issues: {result.status}")
        values = result.items
    else:
        values = result
    if not isinstance(values, (list, tuple)):
        raise RuntimeError("drift issue index returned malformed data")
    return [
        issue
        for issue in values
        if isinstance(issue, dict)
        and issue.get("title")
        and "pull_request" not in issue
    ]


def _ensure_label(client: Any, target_repo: str, label: str) -> None:
    """Create one dedicated label while tolerating GitHub's already-exists response."""
    try:
        client.request(
            "POST",
            f"/repos/{target_repo}/labels",
            {
                "name": label,
                "color": "B60205",
                "description": "Live GitHub Code Scanning analysis drift evidence.",
            },
        )
    except RuntimeError as exc:
        if "422" not in str(exc):
            raise


def publish_records(
    client: Any,
    target_repo: str,
    records: Iterable[PullRequestDriftRecord],
) -> int:
    """Publish bounded confirmed drift while retaining clean and unknown telemetry only."""
    drift_records = [
        record for record in records if record.assessment.status == "drift"
    ]
    if not drift_records:
        return 0
    issues = {
        str(issue.get("title")): issue
        for issue in _issue_items(client, target_repo)
    }
    ensured_labels: set[str] = set()
    published = 0
    for record in drift_records:
        if published >= MAX_ISSUE_UPDATES_PER_RUN:
            break
        title = drift_issue_title(record)
        body = render_drift_issue(record)
        marker = parse_drift_marker(body)
        existing = issues.get(title)
        if existing is not None:
            previous = parse_drift_marker(existing.get("body"))
            if previous.get("evidence_key") == marker.get("evidence_key"):
                continue
            data: dict[str, Any] = {"body": body}
            if existing.get("state") == "closed":
                data["state"] = "open"
            client.request(
                "PATCH",
                f"/repos/{target_repo}/issues/{existing['number']}",
                data,
            )
            client.request(
                "POST",
                f"/repos/{target_repo}/issues/{existing['number']}/comments",
                {
                    "body": (
                        "Live Code Scanning drift evidence changed for this exact "
                        "head.\n\n" + _identity_rows(record)
                    )
                },
            )
            existing.update(data)
            published += 1
            continue

        repository_label = f"repo:{record.repository.split('/', 1)[-1][:45]}"
        labels = [DRIFT_LABEL, SECURITY_LABEL, repository_label]
        for label in labels:
            if label not in ensured_labels:
                _ensure_label(client, target_repo, label)
                ensured_labels.add(label)
        created = client.request(
            "POST",
            f"/repos/{target_repo}/issues",
            {"title": title, "body": body, "labels": labels},
        )
        issues[title] = (
            created
            if isinstance(created, dict)
            else {"number": 0, "state": "open", "title": title, "body": body}
        )
        published += 1
    return published


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse bounded organization, target, and allowlist inputs for the collector."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--owner",
        default=os.getenv("GITHUB_REPOSITORY_OWNER", "ContextualWisdomLab"),
    )
    parser.add_argument(
        "--target-repo",
        default=os.getenv("GITHUB_REPOSITORY", "ContextualWisdomLab/appguardrail"),
    )
    parser.add_argument(
        "--repositories",
        default=os.getenv("CODE_SCANNING_DRIFT_REPOSITORIES", ""),
    )
    parser.add_argument(
        "--max-pull-requests",
        type=int,
        default=int(
            os.getenv(
                "CODE_SCANNING_DRIFT_MAX_PULL_REQUESTS",
                str(DEFAULT_MAX_PULL_REQUESTS),
            )
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Collect with read scope, publish with issue scope, and print bounded telemetry."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    read_token = (os.getenv("GH_READ_TOKEN") or "").strip()
    write_token = (os.getenv("GH_WRITE_TOKEN") or "").strip()
    if not read_token or not write_token:
        raise SystemExit("GH_READ_TOKEN and GH_WRITE_TOKEN are both required")
    if read_token == write_token:
        raise SystemExit("GH_READ_TOKEN and GH_WRITE_TOKEN must be distinct")
    repositories = parse_repositories(args.owner, args.repositories)
    target_repo = parse_repositories(args.owner, args.target_repo)[0]
    read_client = GitHub(read_token)
    write_client = GitHub(write_token)
    records = collect_records(
        read_client,
        owner=args.owner,
        repositories=repositories,
        max_pull_requests=args.max_pull_requests,
    )
    published = publish_records(write_client, target_repo, records)
    summary = {
        "clean": sum(record.assessment.status == "clean" for record in records),
        "drift": sum(record.assessment.status == "drift" for record in records),
        "published": published,
        "total": len(records),
        "unknown": sum(record.assessment.status == "unknown" for record in records),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
