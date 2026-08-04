#!/usr/bin/env python3
"""Collect fail-closed GitHub Code Scanning analysis drift evidence."""

from __future__ import annotations

import re
import urllib.error
from dataclasses import dataclass
from typing import Any, Iterable

from appguardrail_core.code_scanning import (
    AnalysisSnapshot,
    DriftAssessment,
    build_snapshot,
    compare_snapshots,
)
from scripts.ci.commercial_readiness_loop import (
    GitHub as _BaseGitHub,
    NoRedirect,
)


DEFAULT_MAX_PULL_REQUESTS = 100
MAX_PAGINATION_PAGES = 100
_REPOSITORY_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


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
