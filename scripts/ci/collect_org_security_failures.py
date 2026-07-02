#!/usr/bin/env python3
"""Collect organization security workflow failures into AppGuardrail issues."""

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
from typing import Any

API = "https://api.github.com"
UA = "appguardrail-org-security-failure-collector"
FAILURES = {"failure", "cancelled", "timed_out", "action_required"}
SECURITY_TERMS = ("strix", "opencode", "appguardrail", "trivy", "codeql", "security process")
ISSUE_LABEL = "org-security-failure"
SECURITY_LABEL = "security-ci"
MARKER_PREFIX = "<!-- appguardrail-org-security-failure:"
MARKER_SUFFIX = "-->"
DEFAULT_LOOKBACK_HOURS = 48
DEFAULT_MAX_LOG_CHARS = 30_000
DEFAULT_MAX_LOG_LINES = 200

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TS_RE = re.compile(r"^\ufeff?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s*")
SECRET_RE = [
    re.compile(r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+"),
    re.compile(r"(?i)\b((?:api[_-]?key|token|secret|password|private[_-]?key)\s*[:=]\s*)['\"]?[^'\"\s]+"),
    re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
]
PRIMARY_LOG_RE = [
    re.compile(p, re.IGNORECASE)
    for p in (
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
FALLBACK_LOG_RE = [re.compile(r"\bfailed\b|\berror\b|\bfatal\b", re.IGNORECASE)]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token: str, api: str = API):
        self.token = token
        self.api = api.rstrip("/")

    def request(self, method: str, path: str, data: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> Any:
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(
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
            with urllib.request.urlopen(req, timeout=30) as res:
                payload = res.read()
                content_type = res.headers.get("content-type", "")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API {method} {path} failed: {exc.code} {detail}") from exc
        if not payload:
            return None
        text = payload.decode("utf-8", errors="replace")
        return json.loads(text) if "application/json" in content_type else text

    def pages(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
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
        path = f"/repos/{repo}/actions/jobs/{job_id}/logs"
        req = urllib.request.Request(
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
            with urllib.request.urlopen(urllib.request.Request(location, headers={"User-Agent": UA}), timeout=30) as res:
                return res.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            return f"Could not fetch job log: GitHub download failed: {exc.code} {detail}"


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def is_failure(conclusion: str | None) -> bool:
    return (conclusion or "").lower() in FAILURES


def is_security_name(*names: str | None) -> bool:
    text = " ".join(name or "" for name in names).lower()
    return any(term in text for term in SECURITY_TERMS)


def parse_run_url(url: str) -> tuple[str, int]:
    match = re.search(r"github\.com/([^/]+/[^/]+)/actions/runs/(\d+)", url)
    if not match:
        raise ValueError(f"Unsupported GitHub Actions run URL: {url}")
    return match.group(1), int(match.group(2))


def sanitize_label_value(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._:-]+", "-", value.strip()).strip("-")
    return value[:45] or "unknown"


def redact(log: str) -> str:
    text = ANSI_RE.sub("", log.replace("\r\n", "\n").replace("\r", "\n"))
    text = "\n".join(TS_RE.sub("", line) for line in text.splitlines())
    for regex in SECRET_RE:
        text = regex.sub(lambda m: f"{m.group(1)}[REDACTED]" if m.lastindex else "[REDACTED]", text)
    return text


def log_ranges(lines: list[str], patterns: list[re.Pattern[str]]) -> list[tuple[int, int]]:
    return [
        (max(0, i - 2), min(len(lines), i + 9))
        for i, line in enumerate(lines)
        if any(pattern.search(line) for pattern in patterns)
    ]


def compress_log(log: str, max_lines: int = DEFAULT_MAX_LOG_LINES, max_chars: int = DEFAULT_MAX_LOG_CHARS) -> str:
    lines = redact(log).splitlines()
    if not lines:
        return "(no job log returned)"
    ranges = log_ranges(lines, PRIMARY_LOG_RE) or log_ranges(lines, FALLBACK_LOG_RE)
    if not ranges:
        selected = lines[-max_lines:]
    else:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        chosen: list[tuple[int, int]] = []
        count = 0
        for start, end in reversed(merged):
            chosen.append((start, end))
            count += end - start + (1 if len(chosen) > 1 else 0)
            if count >= max_lines:
                break
        selected = []
        for start, end in sorted(chosen):
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


def seen_key(finding: dict[str, Any]) -> str:
    return f"{finding['run_id']}:{finding['job_id']}"


def marker(repo: str, workflow: str, seen: set[str]) -> str:
    payload = {"repo": repo, "workflow": workflow, "seen": sorted(seen)}
    return f"{MARKER_PREFIX} {json.dumps(payload, sort_keys=True)} {MARKER_SUFFIX}"


def parse_marker(body: str | None) -> dict[str, Any]:
    body = body or ""
    start = body.find(MARKER_PREFIX)
    end = body.find(MARKER_SUFFIX, start + len(MARKER_PREFIX))
    if start == -1 or end == -1:
        return {"seen": []}
    try:
        return json.loads(body[start + len(MARKER_PREFIX):end].strip())
    except json.JSONDecodeError:
        return {"seen": []}


def replace_marker(body: str | None, repo: str, workflow: str, seen: set[str]) -> str:
    body = body or ""
    new_marker = marker(repo, workflow, seen)
    start = body.find(MARKER_PREFIX)
    end = body.find(MARKER_SUFFIX, start + len(MARKER_PREFIX))
    if start == -1 or end == -1:
        return f"{new_marker}\n\n{body}".strip()
    return f"{body[:start]}{new_marker}{body[end + len(MARKER_SUFFIX):]}".strip()


def title(finding: dict[str, Any]) -> str:
    return f"[security-failure] {finding['repo']}: {finding['workflow']}"


def summary(finding: dict[str, Any]) -> str:
    prs = ", ".join(f"#{number}" for number in finding["pr_numbers"]) or "n/a"
    rows = [
        ("Repository", f"`{finding['repo']}`"),
        ("Workflow", f"`{finding['workflow']}`"),
        ("Job", f"`{finding['job_name']}`"),
        ("Conclusion", f"`{finding['conclusion']}`"),
        ("Branch", f"`{finding['branch']}`"),
        ("Head SHA", f"`{finding['head_sha']}`"),
        ("Event", f"`{finding['event']}`"),
        ("PRs", prs),
        ("Run", finding["run_url"]),
        ("Job", finding["job_url"]),
    ]
    return "\n".join(f"- {key}: {value}" for key, value in rows)


def issue_body(finding: dict[str, Any], seen: set[str]) -> str:
    owner = finding["repo"].split("/", 1)[0]
    return "\n\n".join(
        [
            marker(finding["repo"], finding["workflow"], seen),
            f"Automated collection of security workflow failures across {owner}.",
            summary(finding),
            f"```text\n{finding['snippet']}\n```",
        ]
    )


def issue_comment(finding: dict[str, Any]) -> str:
    return "\n\n".join(["New security workflow failure detected.", summary(finding), f"```text\n{finding['snippet']}\n```"])


def build_finding(client: GitHub, repo: str, run: dict[str, Any], job: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
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
        "pr_numbers": [pr["number"] for pr in run.get("pull_requests", []) if pr.get("number")],
        "snippet": compress_log(client.job_log(repo, job_id), args.max_log_lines, args.max_log_chars),
    }


def collect_findings(client: GitHub, args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.run_url:
        repo, run_id = parse_run_url(args.run_url)
        repos = [{"full_name": repo}]
        fixed_runs = {repo: [client.request("GET", f"/repos/{repo}/actions/runs/{run_id}")]}
    else:
        repos = [r for r in client.pages("/installation/repositories") if r.get("full_name") and not r.get("archived") and not r.get("fork")]
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
                for r in client.pages(f"/repos/{repo}/actions/runs", {"status": "completed"})
                if is_failure(r.get("conclusion")) and parse_time(r.get("updated_at") or r.get("created_at")) >= cutoff
            ]
        for run in runs:
            for job in client.pages(f"/repos/{repo}/actions/runs/{run['id']}/jobs"):
                if is_failure(job.get("conclusion") or run.get("conclusion")) and is_security_name(run.get("name"), job.get("workflow_name"), job.get("name")):
                    findings.append(build_finding(client, repo, run, job, args))
    return findings


def ensure_label(client: GitHub, target_repo: str, name: str, dry_run: bool, cache: set[str]) -> None:
    if name in cache:
        return
    cache.add(name)
    if dry_run:
        print(f"DRY_RUN label {target_repo}: {name}")
        return
    try:
        client.request("POST", f"/repos/{target_repo}/labels", {"name": name, "color": "B60205", "description": "Automated AppGuardrail security failure collection."})
    except RuntimeError as exc:
        if "422" not in str(exc):
            raise


def issue_index(client: GitHub, target_repo: str) -> dict[str, dict[str, Any]]:
    issues = client.pages(f"/repos/{target_repo}/issues", {"state": "all", "labels": ISSUE_LABEL})
    return {issue["title"]: issue for issue in issues if issue.get("title") and "pull_request" not in issue}


def publish_one(client: GitHub, target_repo: str, finding: dict[str, Any], dry_run: bool, issues: dict[str, dict[str, Any]], labels_seen: set[str]) -> None:
    labels = [ISSUE_LABEL, SECURITY_LABEL, f"repo:{sanitize_label_value(finding['repo'].split('/', 1)[1])}"]
    issue_title = title(finding)
    issue = issues.get(issue_title)
    if issue is None:
        for label in labels:
            ensure_label(client, target_repo, label, dry_run, labels_seen)
        seen = {seen_key(finding)}
        body = issue_body(finding, seen)
        if dry_run:
            print(f"DRY_RUN create issue: {issue_title}\n{body}\n")
            issues[issue_title] = {"number": "dry-run", "state": "open", "title": issue_title, "body": body}
            return
        created = client.request("POST", f"/repos/{target_repo}/issues", {"title": issue_title, "body": body, "labels": labels})
        issues[issue_title] = created if isinstance(created, dict) else {"state": "open", "title": issue_title, "body": body}
        print(f"created issue for {finding['repo']} {finding['workflow']} {seen_key(finding)}")
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
        print(f"DRY_RUN {'reopen/update' if reopen else 'update'} issue #{issue['number']}: {issue_title}")
        print(issue_comment(finding))
    else:
        data = {"state": "open", "body": body} if reopen else {"body": body}
        client.request("PATCH", f"/repos/{target_repo}/issues/{issue['number']}", data)
        client.request("POST", f"/repos/{target_repo}/issues/{issue['number']}/comments", {"body": issue_comment(finding)})
        print(f"updated issue #{issue['number']} for {finding['repo']} {finding['workflow']} {key}")
    issue["body"] = body
    if reopen:
        issue["state"] = "open"


def publish_findings(client: GitHub, target_repo: str, findings: list[dict[str, Any]], dry_run: bool) -> None:
    issues = issue_index(client, target_repo) if findings else {}
    labels_seen: set[str] = set()
    for finding in findings:
        publish_one(client, target_repo, finding, dry_run, issues, labels_seen)


def parse_bool(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default=os.getenv("GITHUB_REPOSITORY_OWNER", "ContextualWisdomLab"))
    parser.add_argument("--target-repo", default=os.getenv("GITHUB_REPOSITORY", "ContextualWisdomLab/appguardrail"))
    parser.add_argument("--lookback-hours", type=int, default=int(os.getenv("LOOKBACK_HOURS", DEFAULT_LOOKBACK_HOURS)))
    parser.add_argument("--max-log-lines", type=int, default=DEFAULT_MAX_LOG_LINES)
    parser.add_argument("--max-log-chars", type=int, default=DEFAULT_MAX_LOG_CHARS)
    parser.add_argument("--run-url", help="Collect one GitHub Actions run URL for dry-run validation.")
    parser.add_argument("--dry-run", action="store_true", default=parse_bool(os.getenv("DRY_RUN")))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
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
