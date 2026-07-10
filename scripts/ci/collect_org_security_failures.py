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

from appguardrail_core.issueops import (DEFAULT_MAX_LOG_CHARS,
                                        DEFAULT_MAX_LOG_LINES, compress_log,
                                        is_failure, is_security_name,
                                        issue_body, issue_comment,
                                        parse_marker, parse_run_url,
                                        replace_marker, sanitize_label_value,
                                        seen_key, title)

API = "https://api.github.com"
UA = "appguardrail-org-security-failure-collector"
ISSUE_LABEL = "org-security-failure"
SECURITY_LABEL = "security-ci"
DEFAULT_LOOKBACK_HOURS = 48
BLOCKED_LOG_HOSTS = {"localhost", "127.0.0.1", "169.254.169.254", "0.0.0.0", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that exposes GitHub log download redirects safely."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Prevent automatic redirect following so the caller can validate URLs."""
        return None


class SecureRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that validates every GitHub log download hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Validate redirected log URLs before urllib opens them."""
        _validate_log_download_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _redacted_url(parsed: urllib.parse.ParseResult) -> str:
    """Return a credential-free URL string safe for error messages."""
    return f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path}"


def _validate_log_download_url(url: str) -> urllib.parse.ParseResult:
    """Reject non-HTTP(S), credentialed, or internal log download URLs."""
    import ipaddress

    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise urllib.error.URLError(
            f"Invalid or dangerous URL scheme in location: {_redacted_url(parsed)}"
        )
    if parsed.username or parsed.password:
        raise urllib.error.URLError(
            f"Credentials not allowed in URL: {_redacted_url(parsed)}"
        )
    host = (parsed.hostname or "").lower()
    if host in BLOCKED_LOG_HOSTS:
        raise urllib.error.URLError(
            f"Access to internal address blocked: {_redacted_url(parsed)}"
        )
    raw = host.split("%", 1)[0].strip("[]")
    if raw.isdigit():  # dotless decimal numeric host
        raise urllib.error.URLError(
            f"Access to internal address blocked: {_redacted_url(parsed)}"
        )

    # Check for octal/hex IP formats that urllib might accept but ipaddress rejects
    parts = raw.split(".")
    if any(p.startswith("0") and len(p) > 1 and p != "0" for p in parts) or any(
        p.startswith("0x") for p in parts
    ):
        raise urllib.error.URLError(
            f"Access to internal address blocked: {_redacted_url(parsed)}"
        )

    try:
        ip = ipaddress.ip_address(raw)
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_multicast
        ):
            raise urllib.error.URLError(
                f"Access to internal address blocked: {_redacted_url(parsed)}"
            )
    except ValueError:
        # Host is not a direct IP literal; allow normal DNS-hostname handling.
        return parsed
    return parsed


class GitHub:
    """Small GitHub REST client for workflow, job, issue, and log APIs."""

    def __init__(self, token: str, api: str = API):
        """Create a client using a bearer token and API root."""
        self.token = token
        self.api = api.rstrip("/")
        # Security concern: Prevent Server-Side Request Forgery (SSRF) and Local File Inclusion (LFI)
        # by ensuring the API base URL only uses secure, safe HTTP schemes before opening connections.
        if not self.api.startswith(("http://", "https://")):
            raise ValueError("API URL must start with http:// or https://")

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Send one JSON GitHub API request and return the decoded payload."""
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(  # noqa: S310 - GitHub API URL
            f"{self.api}{path}{query}",
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
            with urllib.request.urlopen(  # noqa: S310 - GitHub API URL
                req, timeout=30
            ) as res:
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

    def job_log(self, repo: str, job_id: int) -> str:
        """Fetch a job log through GitHub's validated redirected download URL."""
        path = f"/repos/{repo}/actions/jobs/{job_id}/logs"
        req = urllib.request.Request(  # noqa: S310 - GitHub API URL
            f"{self.api}{path}",
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": UA,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            opener = urllib.request.build_opener(NoRedirect)
            with opener.open(req, timeout=30) as res:
                location = res.geturl()
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("location")
            if not (300 <= exc.code < 400 and location):
                detail = exc.read().decode("utf-8", errors="replace")
                return f"Could not fetch job log: GitHub API GET {path} failed: {exc.code} {detail}"
        try:
            _validate_log_download_url(location)
            download_req = (
                urllib.request.Request(  # noqa: S310 - GitHub log redirect URL
                    location, headers={"User-Agent": UA}
                )
            )
            opener = urllib.request.build_opener(SecureRedirectHandler)
            with opener.open(download_req, timeout=30) as res:
                return res.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            return (
                f"Could not fetch job log: GitHub download failed: {exc.code} {detail}"
            )
        except urllib.error.URLError as exc:
            return f"Could not fetch job log: {exc.reason}"


def utc_now() -> dt.datetime:
    """Return the current UTC timestamp with timezone information."""
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: str) -> dt.datetime:
    """Parse GitHub ISO timestamps and ensure the result is timezone-aware."""
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def build_finding(
    client: GitHub,
    repo: str,
    run: dict[str, Any],
    job: dict[str, Any],
    args: argparse.Namespace,
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
        "snippet": compress_log(
            client.job_log(repo, job_id), args.max_log_lines, args.max_log_chars
        ),
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
                    findings.append(build_finding(client, repo, run, job, args))
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
        data = {"state": "open", "body": body} if reopen else {"body": body}
        client.request("PATCH", f"/repos/{target_repo}/issues/{issue['number']}", data)
        client.request(
            "POST",
            f"/repos/{target_repo}/issues/{issue['number']}/comments",
            {"body": issue_comment(finding)},
        )
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
    parser.add_argument("--max-log-lines", type=int, default=DEFAULT_MAX_LOG_LINES)
    parser.add_argument("--max-log-chars", type=int, default=DEFAULT_MAX_LOG_CHARS)
    parser.add_argument(
        "--run-url", help="Collect one GitHub Actions run URL for dry-run validation."
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=parse_bool(os.getenv("DRY_RUN"))
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run collection and issue publication, returning a process exit code."""
    args = parse_args(argv or sys.argv[1:])
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GH_TOKEN or GITHUB_TOKEN is required")
    client = GitHub(token)
    findings = collect_findings(client, args)
    print(f"collected {len(findings)} security workflow failure job(s)")
    publish_findings(client, args.target_repo, findings, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
