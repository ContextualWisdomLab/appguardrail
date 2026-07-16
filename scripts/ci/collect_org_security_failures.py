#!/usr/bin/env python3
"""Collect organization security workflow failures into AppGuardrail issues."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from appguardrail_core.issueops import (
    is_failure,
    is_security_name,
    issue_body,
    issue_comment,
    parse_marker,
    parse_run_url,
    replace_marker,
    sanitize_label_value,
    seen_key,
    title,
)

API = "https://api.github.com"
UA = "appguardrail-org-security-failure-collector"
ISSUE_LABEL = "org-security-failure"
SECURITY_LABEL = "security-ci"
DEFAULT_LOOKBACK_HOURS = 48


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so an authenticated request cannot change origins."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return no follow-up request, causing urllib to raise for redirects."""
        return None


class GitHub:
    """Small GitHub REST client for workflow, job, and issue APIs."""

    def __init__(self, token: str):
        """Create a client whose bearer token is pinned to GitHub's API origin."""
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Send one JSON GitHub API request and return the decoded payload."""
        if not path.startswith("/"):
            raise ValueError("GitHub API path must start with /")
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(  # noqa: S310 - GitHub API URL
            f"{API}{path}{query}",
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": UA,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self.opener.open(req, timeout=30) as res:  # noqa: S310
                payload = res.read()
                content_type = res.headers.get("content-type", "")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub API {method} {path} failed: {exc.code} {detail}"
            ) from exc
        if not payload:
            return None
        text = payload.decode("utf-8", errors="replace")
        return json.loads(text) if "application/json" in content_type else text

    def pages(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
        """Collect all pages for common GitHub list endpoints."""
        items: list[Any] = []
        page = 1
        while True:
            page_params = dict(params or {}, per_page=100, page=page)
            payload = self.request("GET", path, params=page_params)
            chunk = payload
            for key in ("repositories", "workflow_runs", "jobs"):
                if isinstance(payload, dict) and key in payload:
                    chunk = payload[key]
                    break
            if not chunk:
                return items
            items.extend(chunk)
            if len(chunk) < 100:
                return items
            page += 1


def utc_now() -> dt.datetime:
    """Return the current UTC timestamp with timezone information."""
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: str) -> dt.datetime:
    """Parse GitHub ISO timestamps and ensure the result is timezone-aware."""
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def failure_metadata_summary(job: dict[str, Any]) -> str:
    """Render non-sensitive GitHub metadata without copying source-repository logs."""
    raw_conclusion = str(job.get("conclusion") or "").strip().lower()
    conclusion = raw_conclusion if is_failure(raw_conclusion) else "unknown"
    failed_step_numbers = sorted(
        {
            number
            for step in (job.get("steps") or [])
            if isinstance(step, dict)
            and is_failure(str(step.get("conclusion") or "").strip().lower())
            and isinstance((number := step.get("number")), int)
            and number > 0
        }
    )
    step_evidence = (
        ", ".join(str(number) for number in failed_step_numbers)
        if failed_step_numbers
        else "not reported by GitHub"
    )
    return (
        "Trusted GitHub Actions metadata only; raw job logs are intentionally not "
        "copied across repositories.\n"
        f"Job conclusion: {conclusion}.\n"
        f"Failed step numbers: {step_evidence}.\n"
        "Open the source job URL with source-repository authorization for full logs."
    )


def build_finding(
    repo: str,
    run: dict[str, Any],
    job: dict[str, Any],
) -> dict[str, Any]:
    """Build one normalized security workflow failure record from run/job data."""
    job_id = int(job["id"])
    return {
        "repo": repo,
        "workflow": run.get("name") or job.get("workflow_name") or "unknown workflow",
        "run_id": int(run["id"]),
        "run_url": run.get("html_url") or "",
        "job_id": job_id,
        "job_name": job.get("name") or "unknown job",
        "job_url": job.get("html_url") or "",
        "conclusion": job.get("conclusion") or run.get("conclusion") or "unknown",
        "branch": run.get("head_branch") or "",
        "head_sha": run.get("head_sha") or "",
        "event": run.get("event") or "",
        "pr_numbers": [
            pr["number"] for pr in run.get("pull_requests", []) if pr.get("number")
        ],
        "snippet": failure_metadata_summary(job),
    }


def collect_findings(client: GitHub, args: argparse.Namespace) -> list[dict[str, Any]]:
    """Collect failed security workflow jobs across the configured organization."""
    if args.run_url:
        repo, run_id = parse_run_url(args.run_url)
        repos = [{"full_name": repo}]
        fixed_runs = {
            repo: [client.request("GET", f"/repos/{repo}/actions/runs/{run_id}")]
        }
    else:
        repos = [
            r
            for r in client.pages("/installation/repositories")
            if r.get("full_name") and not r.get("archived") and not r.get("fork")
        ]
        fixed_runs = {}
    cutoff = utc_now() - dt.timedelta(hours=args.lookback_hours)
    findings: list[dict[str, Any]] = []
    for repo_info in repos:
        repo = repo_info["full_name"]
        if not repo.startswith(f"{args.owner}/"):
            continue
        runs = fixed_runs.get(repo)
        if runs is None:
            runs = [
                r
                for r in client.pages(
                    f"/repos/{repo}/actions/runs", {"status": "completed"}
                )
                if is_failure(r.get("conclusion"))
                and parse_time(r.get("updated_at") or r.get("created_at")) >= cutoff
            ]
        for run in runs:
            for job in client.pages(f"/repos/{repo}/actions/runs/{run['id']}/jobs"):
                if is_failure(
                    job.get("conclusion") or run.get("conclusion")
                ) and is_security_name(
                    run.get("name"), job.get("workflow_name"), job.get("name")
                ):
                    findings.append(build_finding(repo, run, job))
    return findings


def ensure_label(
    client: GitHub, target_repo: str, name: str, dry_run: bool, cache: set[str]
) -> None:
    """Ensure a GitHub issue label exists, caching labels within one run."""
    if name in cache:
        return
    cache.add(name)
    if dry_run:
        print(f"DRY_RUN label {target_repo}: {name}")
        return
    try:
        client.request(
            "POST",
            f"/repos/{target_repo}/labels",
            {
                "name": name,
                "color": "B60205",
                "description": "Automated AppGuardrail security failure collection.",
            },
        )
    except RuntimeError as exc:
        if "422" not in str(exc):
            raise


def issue_index(client: GitHub, target_repo: str) -> dict[str, dict[str, Any]]:
    """Return existing non-PR issues keyed by title for deduplication."""
    issues = client.pages(
        f"/repos/{target_repo}/issues", {"state": "all", "labels": ISSUE_LABEL}
    )
    return {
        issue["title"]: issue
        for issue in issues
        if issue.get("title") and "pull_request" not in issue
    }


def publish_one(
    client: GitHub,
    target_repo: str,
    finding: dict[str, Any],
    dry_run: bool,
    issues: dict[str, dict[str, Any]],
    labels_seen: set[str],
) -> None:
    """Create, reopen, or update one issue for a collected failure."""
    labels = [
        ISSUE_LABEL,
        SECURITY_LABEL,
        f"repo:{sanitize_label_value(finding['repo'].split('/', 1)[1])}",
    ]
    issue_title = title(finding)
    issue = issues.get(issue_title)
    if issue is None:
        for label in labels:
            ensure_label(client, target_repo, label, dry_run, labels_seen)
        seen = {seen_key(finding)}
        body = issue_body(finding, seen)
        if dry_run:
            print(f"DRY_RUN create issue: {issue_title}\n{body}\n")
            issues[issue_title] = {
                "number": "dry-run",
                "state": "open",
                "title": issue_title,
                "body": body,
            }
            return
        created = client.request(
            "POST",
            f"/repos/{target_repo}/issues",
            {"title": issue_title, "body": body, "labels": labels},
        )
        issues[issue_title] = (
            created
            if isinstance(created, dict)
            else {"state": "open", "title": issue_title, "body": body}
        )
        print(
            f"created issue for {finding['repo']} {finding['workflow']} {seen_key(finding)}"
        )
        return

    seen = set(parse_marker(issue.get("body")).get("seen", []))
    key = seen_key(finding)
    if key in seen:
        print(f"skip duplicate {finding['repo']} {finding['workflow']} {key}")
        return
    reopen = issue.get("state") == "closed"
    seen.add(key)
    body = replace_marker(issue.get("body"), finding["repo"], finding["workflow"], seen)
    if dry_run:
        print(
            f"DRY_RUN {'reopen/update' if reopen else 'update'} issue #{issue['number']}: {issue_title}"
        )
        print(issue_comment(finding))
    else:
        # Deliver the alert before committing its deduplication marker. If the
        # comment request fails, the next collector loop must retry the finding
        # instead of silently treating an undelivered alert as seen.
        client.request(
            "POST",
            f"/repos/{target_repo}/issues/{issue['number']}/comments",
            {"body": issue_comment(finding)},
        )
        data = {"state": "open", "body": body} if reopen else {"body": body}
        client.request("PATCH", f"/repos/{target_repo}/issues/{issue['number']}", data)
        print(
            f"updated issue #{issue['number']} for {finding['repo']} {finding['workflow']} {key}"
        )
    issue["body"] = body
    if reopen:
        issue["state"] = "open"


def publish_findings(
    client: GitHub, target_repo: str, findings: list[dict[str, Any]], dry_run: bool
) -> None:
    """Publish every collected failure to the target repository."""
    issues = issue_index(client, target_repo) if findings else {}
    labels_seen: set[str] = set()
    for finding in findings:
        publish_one(client, target_repo, finding, dry_run, issues, labels_seen)


def parse_bool(value: str | None) -> bool:
    """Parse truthy environment-style strings."""
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments for the collector."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--owner", default=os.getenv("GITHUB_REPOSITORY_OWNER", "ContextualWisdomLab")
    )
    parser.add_argument(
        "--target-repo",
        default=os.getenv("GITHUB_REPOSITORY", "ContextualWisdomLab/appguardrail"),
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=int(os.getenv("LOOKBACK_HOURS", DEFAULT_LOOKBACK_HOURS)),
    )
    parser.add_argument(
        "--run-url", help="Collect one GitHub Actions run URL for dry-run validation."
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=parse_bool(os.getenv("DRY_RUN"))
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run collection and issue publication, returning a process exit code."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    read_token = (os.getenv("GH_READ_TOKEN") or "").strip()
    write_token = (os.getenv("GH_WRITE_TOKEN") or "").strip()
    if not read_token or not write_token:
        raise SystemExit(
            "GH_READ_TOKEN and GH_WRITE_TOKEN are both required; use separate "
            "allowlisted read and target-only issue-write installation tokens"
        )
    if read_token == write_token:
        raise SystemExit(
            "GH_READ_TOKEN and GH_WRITE_TOKEN must be distinct least-privilege credentials"
        )
    read_client = GitHub(read_token)
    write_client = GitHub(write_token)
    findings = collect_findings(read_client, args)
    print(f"collected {len(findings)} security workflow failure job(s)")
    publish_findings(write_client, args.target_repo, findings, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
