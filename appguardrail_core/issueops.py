"""Reusable IssueOps helpers for security workflow failure handling."""

from __future__ import annotations

import json
import re
from typing import Any

FAILURES = {"failure", "cancelled", "timed_out", "action_required"}
SECURITY_TERMS = ("strix", "opencode", "appguardrail", "trivy", "codeql", "security process")
MARKER_PREFIX = "<!-- appguardrail-org-security-failure:"
MARKER_SUFFIX = "-->"
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
FALLBACK_LOG_RE = [re.compile(r"\bfailed\b|\berror\b|\bfatal\b", re.IGNORECASE)]


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
        text = regex.sub(lambda match: f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]", text)
    return text


def log_ranges(lines: list[str], patterns: list[re.Pattern[str]]) -> list[tuple[int, int]]:
    return [
        (max(0, index - 2), min(len(lines), index + 9))
        for index, line in enumerate(lines)
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
