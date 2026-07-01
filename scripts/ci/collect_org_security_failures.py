#!/usr/bin/env python3
"""Collect org security workflow failures into AppGuardrail issues."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

API = "https://api.github.com"
USER_AGENT = "appguardrail-org-security-failure-collector"
FAILURE_CONCLUSIONS = {"failure", "cancelled", "timed_out", "action_required"}
SECURITY_TERMS = (
    "strix",
    "opencode",
    "appguardrail",
    "trivy",
    "codeql",
    "security process",
)
ISSUE_LABEL = "org-security-failure"
SECURITY_LABEL = "security-ci"
MARKER_PREFIX = "<!-- appguardrail-org-security-failure:"
MARKER_SUFFIX = "-->"
DEFAULT_LOOKBACK_HOURS = 48
DEFAULT_MAX_LOG_CHARS = 30_000
DEFAULT_MAX_LOG_LINES = 200

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TIMESTAMP_RE = re.compile(r"^\ufeff?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s*")
SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+"),
    re.compile(r"(?i)\b((?:api[_-]?key|token|secret|password|private[_-]?key)\s*[:=]\s*)['\"]?[^'\"\s]+"),
    re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
]
PRIORITY_LOG_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"^\s*::error::",
        r"traceback",
        r"vuln-",
        r"\bcritical\b",
        r"\bhigh\b",
        r"ratelimiterror",
        r"unable to map strix findings",
        r"\btimeout\b|\btimed out\b",
    )
]
FALLBACK_LOG_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bfailed\b|\berror\b|\bfatal\b",
    )
]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class Finding:
    repo: str
    workflow: str
    run_id: int
    run_url: str
    job_id: int
    job_name: str
    job_url: str
    conclusion: str
    branch: str
    head_sha: str
    event: str
    pr_numbers: tuple[int, ...]
    snippet: str

    @property
    def seen_key(self) -> str:
        return f"{self.run_id}:{self.job_id}"


class GitHubClient:
    def __init__(self, token: str, api: str = API):
        self.token = token
        self.api = api.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        accept: str = "application/vnd.github+json",
    ) -> Any:
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        url = f"{self.api}{path}{query}"
        body = json.dumps(data).encode("utf-8") if data is not None else None
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Accept": accept,
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read()
                content_type = response.headers.get("content-type", "")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API {method} {path} failed: {exc.code} {detail}") from exc
        if not payload:
            return None
        if "application/json" in content_type:
            return json.loads(payload.decode("utf-8"))
        return payload.decode("utf-8", errors="replace")

    def paginate(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
        items: list[Any] = []
        page = 1
        while True:
            request_params = dict(params or {})
            request_params.update({"per_page": 100, "page": page})
            payload = self.request("GET", path, params=request_params)
            if isinstance(payload, dict) and "repositories" in payload:
                chunk = payload["repositories"]
            elif isinstance(payload, dict) and "workflow_runs" in payload:
                chunk = payload["workflow_runs"]
            elif isinstance(payload, dict) and "jobs" in payload:
                chunk = payload["jobs"]
            else:
                chunk = payload
            if not chunk:
                break
            items.extend(chunk)
            if len(chunk) < 100:
                break
            page += 1
        return items

    def redirect_url(self, path: str) -> str:
        request = urllib.request.Request(
            f"{self.api}{path}",
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": USER_AGENT,
            },
        )
        opener = urllib.request.build_opener(NoRedirectHandler)
        try:
            with opener.open(request, timeout=30) as response:
                return response.geturl()
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("location")
            if 300 <= exc.code < 400 and location:
                return location
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API GET {path} failed: {exc.code} {detail}") from exc

    def download_text(self, url: str) -> str:
        request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub download failed: {exc.code} {detail}") from exc


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_timestamp(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def is_failure_conclusion(conclusion: str | None) -> bool:
    return (conclusion or "").lower() in FAILURE_CONCLUSIONS


def is_security_name(*names: str | None) -> bool:
    joined = " ".join(name or "" for name in names).lower()
    return any(term in joined for term in SECURITY_TERMS)


def sanitize_label_value(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._:-]+", "-", value.strip()).strip("-")
    return cleaned[:45] or "unknown"


def issue_title(repo: str, workflow: str) -> str:
    return f"[security-failure] {repo}: {workflow}"


def strip_log_noise(log: str) -> str:
    text = ANSI_RE.sub("", log.replace("\r\n", "\n").replace("\r", "\n"))
    return "\n".join(TIMESTAMP_RE.sub("", line) for line in text.splitlines())


def redact_log(log: str) -> str:
    redacted = strip_log_noise(log)
    for pattern in SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def log_context_ranges(lines: list[str], patterns: list[re.Pattern[str]]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        if any(pattern.search(line) for pattern in patterns):
            ranges.append((max(0, index - 2), min(len(lines), index + 9)))
    return ranges


def compress_log(log: str, max_lines: int = DEFAULT_MAX_LOG_LINES, max_chars: int = DEFAULT_MAX_LOG_CHARS) -> str:
    lines = redact_log(log).splitlines()
    if not lines:
        return "(no job log returned)"

    ranges = log_context_ranges(lines, PRIORITY_LOG_PATTERNS)
    if not ranges:
        ranges = log_context_ranges(lines, FALLBACK_LOG_PATTERNS)

    if not ranges:
        selected = lines[-max_lines:]
    else:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))

        selected_ranges: list[tuple[int, int]] = []
        selected_count = 0
        for start, end in reversed(merged):
            selected_ranges.append((start, end))
            selected_count += end - start + (1 if len(selected_ranges) > 1 else 0)
            if selected_count >= max_lines:
                break

        selected = []
        for start, end in sorted(selected_ranges):
            if selected:
                selected.append("...")
            selected.extend(lines[start:end])
            if len(selected) >= max_lines:
                break
        selected = selected[:max_lines]

    snippet = "\n".join(selected)
    if len(snippet) > max_chars:
        snippet = snippet[:max_chars].rstrip() + "\n...[truncated]"
    if len(lines) > len(selected):
        snippet += "\n...[compressed]"
    return snippet


def marker_payload(repo: str, workflow: str, seen: set[str]) -> str:
    payload = {"repo": repo, "workflow": workflow, "seen": sorted(seen)}
    return f"{MARKER_PREFIX} {json.dumps(payload, sort_keys=True)} {MARKER_SUFFIX}"


def parse_marker(body: str | None) -> dict[str, Any]:
    body = body or ""
    start = body.find(MARKER_PREFIX)
    if start == -1:
        return {"seen": []}
    start += len(MARKER_PREFIX)
    end = body.find(MARKER_SUFFIX, start)
    if end == -1:
        return {"seen": []}
    try:
        return json.loads(body[start:end].strip())
    except json.JSONDecodeError:
        return {"seen": []}


def replace_marker(body: str | None, repo: str, workflow: str, seen: set[str]) -> str:
    body = body or ""
    marker = marker_payload(repo, workflow, seen)
    start = body.find(MARKER_PREFIX)
    if start == -1:
        return f"{marker}\n\n{body}".strip()
    end = body.find(MARKER_SUFFIX, start)
    if end == -1:
        return f"{marker}\n\n{body}".strip()
    end += len(MARKER_SUFFIX)
    return f"{body[:start]}{marker}{body[end:]}".strip()


def issue_body(finding: Finding, seen: set[str]) -> str:
    return "\n\n".join(
        [
            marker_payload(finding.repo, finding.workflow, seen),
            "Automated collection of security workflow failures across ContextualWisdomLab.",
            finding_summary(finding),
            "```text\n" + finding.snippet + "\n```",
        ]
    )


def finding_summary(finding: Finding) -> str:
    prs = ", ".join(f"#{number}" for number in finding.pr_numbers) or "n/a"
    return "\n".join(
        [
            f"- Repository: `{finding.repo}`",
            f"- Workflow: `{finding.workflow}`",
            f"- Job: `{finding.job_name}`",
            f"- Conclusion: `{finding.conclusion}`",
            f"- Branch: `{finding.branch}`",
            f"- Head SHA: `{finding.head_sha}`",
            f"- Event: `{finding.event}`",
            f"- PRs: {prs}",
            f"- Run: {finding.run_url}",
            f"- Job: {finding.job_url}",
        ]
    )


def issue_comment(finding: Finding) -> str:
    return "\n\n".join(
        [
            "New security workflow failure detected.",
            finding_summary(finding),
            "```text\n" + finding.snippet + "\n```",
        ]
    )


def should_reopen_issue(issue: dict[str, Any], finding: Finding) -> bool:
    return issue.get("state") == "closed" and finding.seen_key not in set(parse_marker(issue.get("body")).get("seen", []))


def collect_repositories(client: GitHubClient) -> list[dict[str, Any]]:
    repos = client.paginate("/installation/repositories")
    return [
        repo
        for repo in repos
        if not repo.get("archived") and not repo.get("fork") and repo.get("full_name")
    ]


def recent_failed_runs(client: GitHubClient, repo: str, cutoff: dt.datetime) -> list[dict[str, Any]]:
    runs = client.paginate(f"/repos/{repo}/actions/runs", {"status": "completed"})
    selected = []
    for run in runs:
        updated_at = parse_timestamp(run.get("updated_at") or run.get("created_at"))
        if updated_at < cutoff:
            continue
        if is_failure_conclusion(run.get("conclusion")):
            selected.append(run)
    return selected


def jobs_for_run(client: GitHubClient, repo: str, run_id: int) -> list[dict[str, Any]]:
    return client.paginate(f"/repos/{repo}/actions/runs/{run_id}/jobs")


def job_log(client: GitHubClient, repo: str, job_id: int) -> str:
    try:
        redirect = client.redirect_url(f"/repos/{repo}/actions/jobs/{job_id}/logs")
        return client.download_text(redirect)
    except RuntimeError as exc:
        return f"Could not fetch job log: {exc}"


def finding_from_run_job(client: GitHubClient, repo: str, run: dict[str, Any], job: dict[str, Any], max_lines: int, max_chars: int) -> Finding:
    log = job_log(client, repo, int(job["id"]))
    prs = tuple(pr.get("number") for pr in run.get("pull_requests", []) if pr.get("number"))
    return Finding(
        repo=repo,
        workflow=run.get("name") or job.get("workflow_name") or "unknown workflow",
        run_id=int(run["id"]),
        run_url=run.get("html_url") or "",
        job_id=int(job["id"]),
        job_name=job.get("name") or "unknown job",
        job_url=job.get("html_url") or "",
        conclusion=job.get("conclusion") or run.get("conclusion") or "unknown",
        branch=run.get("head_branch") or "",
        head_sha=run.get("head_sha") or "",
        event=run.get("event") or "",
        pr_numbers=prs,
        snippet=compress_log(log, max_lines=max_lines, max_chars=max_chars),
    )


def collect_findings(client: GitHubClient, owner: str, lookback_hours: int, max_lines: int, max_chars: int, run_url: str | None = None) -> list[Finding]:
    cutoff = utc_now() - dt.timedelta(hours=lookback_hours)
    findings: list[Finding] = []

    if run_url:
        repo, run_id = parse_run_url(run_url)
        runs = [client.request("GET", f"/repos/{repo}/actions/runs/{run_id}")]
        repos = [{"full_name": repo}]
    else:
        repos = collect_repositories(client)
        runs = []

    for repo_info in repos:
        repo = repo_info["full_name"]
        if not repo.startswith(f"{owner}/"):
            continue
        repo_runs = runs if run_url else recent_failed_runs(client, repo, cutoff)
        for run in repo_runs:
            jobs = jobs_for_run(client, repo, int(run["id"]))
            for job in jobs:
                if not is_failure_conclusion(job.get("conclusion") or run.get("conclusion")):
                    continue
                if not is_security_name(run.get("name"), job.get("workflow_name"), job.get("name")):
                    continue
                findings.append(finding_from_run_job(client, repo, run, job, max_lines, max_chars))
    return findings


def parse_run_url(url: str) -> tuple[str, int]:
    match = re.search(r"github\.com/([^/]+/[^/]+)/actions/runs/(\d+)", url)
    if not match:
        raise ValueError(f"Unsupported GitHub Actions run URL: {url}")
    return match.group(1), int(match.group(2))


def ensure_label(client: GitHubClient, target_repo: str, name: str, color: str, description: str, dry_run: bool) -> None:
    if dry_run:
        print(f"DRY_RUN label {target_repo}: {name}")
        return
    try:
        client.request(
            "POST",
            f"/repos/{target_repo}/labels",
            {"name": name, "color": color, "description": description},
        )
    except RuntimeError as exc:
        if "422" not in str(exc):
            raise


def existing_issue(client: GitHubClient, target_repo: str, title: str) -> dict[str, Any] | None:
    issues = client.paginate(
        f"/repos/{target_repo}/issues",
        {"state": "all", "labels": ISSUE_LABEL},
    )
    for issue in issues:
        if issue.get("title") == title and "pull_request" not in issue:
            return issue
    return None


def publish_finding(client: GitHubClient, target_repo: str, finding: Finding, dry_run: bool) -> None:
    repo_name = finding.repo.split("/", 1)[1]
    labels = [ISSUE_LABEL, SECURITY_LABEL, f"repo:{sanitize_label_value(repo_name)}"]
    for label in labels:
        ensure_label(client, target_repo, label, "B60205", "Automated AppGuardrail security failure collection.", dry_run)

    title = issue_title(finding.repo, finding.workflow)
    issue = existing_issue(client, target_repo, title)
    if issue is None:
        seen = {finding.seen_key}
        body = issue_body(finding, seen)
        if dry_run:
            print(f"DRY_RUN create issue: {title}\n{body}\n")
            return
        client.request("POST", f"/repos/{target_repo}/issues", {"title": title, "body": body, "labels": labels})
        print(f"created issue for {finding.repo} {finding.workflow} {finding.seen_key}")
        return

    marker = parse_marker(issue.get("body"))
    seen = set(marker.get("seen", []))
    if finding.seen_key in seen:
        print(f"skip duplicate {finding.repo} {finding.workflow} {finding.seen_key}")
        return

    seen.add(finding.seen_key)
    new_body = replace_marker(issue.get("body"), finding.repo, finding.workflow, seen)
    if dry_run:
        print(f"DRY_RUN update issue #{issue['number']}: {title}")
        print(issue_comment(finding))
        return

    if should_reopen_issue(issue, finding):
        client.request("PATCH", f"/repos/{target_repo}/issues/{issue['number']}", {"state": "open", "body": new_body})
    else:
        client.request("PATCH", f"/repos/{target_repo}/issues/{issue['number']}", {"body": new_body})
    client.request("POST", f"/repos/{target_repo}/issues/{issue['number']}/comments", {"body": issue_comment(finding)})
    print(f"updated issue #{issue['number']} for {finding.repo} {finding.workflow} {finding.seen_key}")


def parse_bool(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default=os.getenv("GITHUB_REPOSITORY_OWNER", "ContextualWisdomLab"))
    parser.add_argument("--target-repo", default=os.getenv("GITHUB_REPOSITORY", "ContextualWisdomLab/appguardrail"))
    parser.add_argument("--lookback-hours", type=int, default=int(os.getenv("LOOKBACK_HOURS", DEFAULT_LOOKBACK_HOURS)))
    parser.add_argument("--max-log-lines", type=int, default=DEFAULT_MAX_LOG_LINES)
    parser.add_argument("--max-log-chars", type=int, default=DEFAULT_MAX_LOG_CHARS)
    parser.add_argument("--run-url", help="Collect a single GitHub Actions run URL, useful for dry-runs.")
    parser.add_argument("--dry-run", action="store_true", default=parse_bool(os.getenv("DRY_RUN")))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GH_TOKEN or GITHUB_TOKEN is required")

    client = GitHubClient(token)
    findings = collect_findings(
        client,
        owner=args.owner,
        lookback_hours=args.lookback_hours,
        max_lines=args.max_log_lines,
        max_chars=args.max_log_chars,
        run_url=args.run_url,
    )
    print(f"collected {len(findings)} security workflow failure job(s)")
    for finding in findings:
        publish_finding(client, args.target_repo, finding, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
