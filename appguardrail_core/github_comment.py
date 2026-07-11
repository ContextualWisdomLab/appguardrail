"""Post a sticky AppGuardrail findings comment on a GitHub pull request.

Inline annotations show findings on the diff; a single sticky PR comment gives
reviewers the roll-up in one place and updates in place on every push (no comment
spam). Runs inside GitHub Actions using GITHUB_TOKEN — read a findings JSON file
(`scan --findings-json`) and upsert one comment marked with a hidden HTML anchor.

Stdlib only (urllib). Usage: ``python -m appguardrail_core.github_comment <findings.json>``.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Optional

from .github_actions import step_summary_md

MARKER = "<!-- appguardrail-report -->"
_API = "https://api.github.com"


def build_comment(findings: list[dict[str, Any]]) -> str:
    """Markdown body for the sticky comment (reuses the job-summary renderer)."""
    files = len({str(f.get("file")) for f in findings})
    return f"{MARKER}\n{step_summary_md(findings, files)}"


def _pr_number(event_path: Optional[str], ref: Optional[str]) -> Optional[int]:
    """Resolve the PR number from the Actions event payload or ref."""
    ref_pr: Optional[int] = None
    if ref and ref.startswith("refs/pull/"):
        parts = ref.split("/")
        try:
            ref_pr = int(parts[2])
        except (IndexError, ValueError):
            ref_pr = None

    event: Any = None
    if event_path and os.path.exists(event_path):
        try:
            with open(event_path, encoding="utf-8") as fh:
                event = json.load(fh)
        except (OSError, ValueError):
            event = None
    if isinstance(event, dict):
        pr = event.get("pull_request") or {}
        number = pr.get("number") or event.get("number")
        if number is not None:
            try:
                return int(number)
            except (TypeError, ValueError):
                return ref_pr
    return ref_pr


def _request(method: str, url: str, token: str, body: Optional[dict] = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "appguardrail")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read() or "null")


def _find_sticky(repo: str, pr: int, token: str) -> Optional[int]:
    """Return the id of an existing AppGuardrail comment, if any."""
    comments = _request("GET", f"{_API}/repos/{repo}/issues/{pr}/comments?per_page=100", token)
    for c in comments or []:
        if MARKER in (c.get("body") or ""):
            return c.get("id")
    return None


def post(findings: list[dict[str, Any]]) -> str:
    """Upsert the sticky comment. Returns a short status string."""
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        return "skipped: no GITHUB_TOKEN/GITHUB_REPOSITORY"
    pr = _pr_number(os.environ.get("GITHUB_EVENT_PATH"), os.environ.get("GITHUB_REF"))
    if not pr:
        return "skipped: not a pull_request event"

    body = build_comment(findings)
    try:
        existing = _find_sticky(repo, pr, token)
        if existing:
            _request("PATCH", f"{_API}/repos/{repo}/issues/comments/{existing}", token, {"body": body})
            return f"updated comment {existing} on PR #{pr}"
        _request("POST", f"{_API}/repos/{repo}/issues/{pr}/comments", token, {"body": body})
        return f"created comment on PR #{pr}"
    except urllib.error.URLError as exc:
        # A comment failure must never fail the security gate.
        return f"skipped: github api error ({exc})"


def _load(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    return payload.get("findings", payload) if isinstance(payload, dict) else payload


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m appguardrail_core.github_comment <findings.json>", file=sys.stderr)
        return 2
    print(post(_load(argv[0])))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--self-check":  # pragma: no cover
        fs = [
            {"severity": "CRITICAL", "rule_id": "secret", "file": "a.ts", "line": 3,
             "message": "hardcoded", "context": "app-code"},
        ]
        body = build_comment(fs)
        assert body.startswith(MARKER) and "AppGuardrail" in body
        assert _pr_number(None, "refs/pull/42/merge") == 42
        assert _pr_number(None, "refs/heads/main") is None
        print("github_comment self-check OK")
    else:
        raise SystemExit(main(sys.argv[1:]))
