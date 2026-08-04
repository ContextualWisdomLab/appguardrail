#!/usr/bin/env python3
"""Dispatch one reviewed AppGuardrail commercial-readiness gap per idle hour."""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from types import SimpleNamespace
from typing import Any


API = "https://api.github.com"
USER_AGENT = "appguardrail-commercial-readiness-loop"
COMMERCIAL_LABEL = "commercial-readiness"
JULES_LABEL = "jules"
_GAP_MARKER_RE = re.compile(
    r"^<!-- appguardrail-commercial-gap: ([a-z0-9]+(?:-[a-z0-9]+)*) -->$"
)
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class CommercialGap:
    """One reviewed buyer-visible product gap eligible for autonomous dispatch."""

    id: str
    title: str
    objective: str
    acceptance: tuple[str, ...]


@dataclass(frozen=True)
class LoopResult:
    """Machine-readable outcome from one hourly commercial-readiness pass."""

    action: str
    gap_id: str | None
    issue_number: int | None
    pull_requests: tuple[int, ...] = ()


COMMERCIAL_GAPS = (
    CommercialGap(
        id="openssf-best-practices-evidence",
        title="feat(governance): ingest OpenSSF Best Practices evidence",
        objective=(
            "Turn OpenSSF Best Practices participation into auditable product evidence "
            "instead of a binary repository-text guess."
        ),
        acceptance=(
            "Support current and legacy OpenSSF Best Practices project evidence without asserting registration when evidence is unavailable.",
            "Expose badge tier, evidence URL, and verification timestamp through normalized findings and buyer-diligence reports.",
            "Cover unavailable, in-progress, passing, silver, gold, malformed, and permission-limited states.",
            "Resolve or supersede issue #309 only when repository evidence supports closure.",
        ),
    ),
    CommercialGap(
        id="enterprise-retention-audit-policy",
        title="feat(control-plane): add tenant retention and audit policy",
        objective=(
            "Add enterprise-grade data-retention controls and immutable audit evidence "
            "for findings, scan history, API keys, and IssueOps actions."
        ),
        acceptance=(
            "Define tenant-scoped retention policy with safe defaults and explicit owner-only mutation.",
            "Record non-secret audit events for retention, key, webhook, and suppression changes.",
            "Provide deterministic purge preview and execution paths with cross-tenant isolation tests.",
            "Expose retention and audit posture in buyer-diligence output without leaking customer data.",
        ),
    ),
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so the workflow token cannot be forwarded to another origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return no redirected request, causing urllib to raise for the response."""
        return None


class GitHub:
    """Minimal GitHub REST client pinned to the public GitHub API origin."""

    def __init__(self, token: str, api: str = API):
        """Create a client using one workflow-scoped token and a fixed API origin."""
        normalized_api = api.rstrip("/")
        if normalized_api != API:
            raise ValueError("GitHub API root must be https://api.github.com")
        self.token = token
        self.api = normalized_api
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Send one authenticated JSON request and return its decoded response."""
        if not path.startswith("/"):
            raise ValueError("GitHub API path must start with /")
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        body = json.dumps(data).encode("utf-8") if data is not None else None
        request = urllib.request.Request(  # noqa: S310 - origin is fixed above
            f"{self.api}{path}{query}",
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self.opener.open(request, timeout=30) as response:  # noqa: S310
                payload = response.read()
                content_type = response.headers.get("content-type", "")
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
        """Collect all pages from a GitHub list endpoint."""
        items: list[Any] = []
        page = 1
        while True:
            page_params = dict(params or {}, per_page=100, page=page)
            chunk = self.request("GET", path, params=page_params) or []
            if not isinstance(chunk, list):
                raise RuntimeError(
                    f"GitHub list endpoint returned non-list data: {path}"
                )
            items.extend(chunk)
            if len(chunk) < 100:
                return items
            page += 1


def gap_marker(gap_id: str) -> str:
    """Return the exact hidden marker used to identify one reviewed gap issue."""
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", gap_id):
        raise ValueError("gap id must be lower-kebab-case")
    return f"<!-- appguardrail-commercial-gap: {gap_id} -->"


def parse_gap_marker(body: str | None) -> str | None:
    """Return a reviewed gap id from an exact marker line, otherwise ``None``."""
    known = {gap.id for gap in COMMERCIAL_GAPS}
    for line in (body or "").splitlines():
        match = _GAP_MARKER_RE.fullmatch(line)
        if match and match.group(1) in known:
            return match.group(1)
    return None


def render_gap_issue(gap: CommercialGap) -> str:
    """Render a bounded implementation issue suitable for Jules and maintainers."""
    acceptance = "\n".join(f"- [ ] {item}" for item in gap.acceptance)
    return f"""## Buyer-visible gap

{gap.objective}

## Acceptance criteria

{acceptance}

## Autonomous implementation contract

- Write the failing regression test first, confirm the expected RED result, then implement the smallest production change that makes it GREEN.
- Keep public functions, classes, modules, and non-obvious behavior fully documented; preserve 100% docstring and code coverage for changed code.
- Run focused and full validation, address every valid review thread, and never bypass required GitHub Checks or branch protection.
- Research uncertain implementation choices through current authoritative primary documentation or international standards; use Context7 for current library contracts and Consensus for peer-reviewed evidence when the decision benefits from research.
- For UI or workflow-experience changes, use Figma or Product Design before implementation. Use Visualize for quantitative product, quality, or operational evidence when a chart materially improves the decision.
- Update user documentation and `CHANGELOG.md`; bump and release only when the resulting product slice is release-ready.
- Target `develop` and preserve standalone behavior plus modular MSA compatibility with ContextualWisdomLab organization infrastructure and naruon.
- Use descriptive nonnumeric identifiers. New database object names must contain at least two words in snake_case, CamelCase, or PascalCase, with snake_case preferred.
- Keep the PR scoped to this gap. Document material uncertainty rather than claiming evidence that was not observed.
- Include `Closes #<this issue number>` in the PR description so the next hourly pass can advance only after this slice is merged.
- Before completion, remove the completed gap from `COMMERCIAL_GAPS` and append the next evidence-backed buyer-visible gap when one is supported; keep the reviewed backlog bounded and prioritized.

{gap_marker(gap.id)}
"""


def _repository_path(repository: str) -> str:
    """Validate and return an exact owner/repository path component."""
    if not _REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository must use exact owner/name syntax")
    return repository


def _open_pull_requests(client: Any, repository: str) -> tuple[int, ...]:
    """Return sorted positive numbers for all open pull requests."""
    pulls = client.pages(
        f"/repos/{repository}/pulls",
        {"state": "open", "sort": "created", "direction": "asc"},
    )
    numbers = {
        int(pull["number"])
        for pull in pulls
        if isinstance(pull, dict)
        and str(pull.get("number", "")).isdigit()
        and int(pull["number"]) > 0
    }
    return tuple(sorted(numbers))


def _gap_issues(client: Any, repository: str) -> list[dict[str, Any]]:
    """Return non-PR issues carrying the commercial-readiness label."""
    return [
        issue
        for issue in client.pages(
            f"/repos/{repository}/issues",
            {"state": "all", "labels": COMMERCIAL_LABEL},
        )
        if isinstance(issue, dict) and "pull_request" not in issue
    ]


def _ensure_label(client: Any, repository: str, name: str, description: str) -> None:
    """Create an issue label when absent, tolerating GitHub's duplicate response."""
    try:
        client.request(
            "POST",
            f"/repos/{repository}/labels",
            {"name": name, "color": "1D76DB", "description": description},
        )
    except RuntimeError as exc:
        if "422" not in str(exc):
            raise


def _active_and_completed(
    issues: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Index active reviewed gaps and completed gap identities from issue state."""
    active: dict[str, dict[str, Any]] = {}
    completed: set[str] = set()
    for issue in issues:
        gap_id = parse_gap_marker(issue.get("body"))
        if not gap_id:
            continue
        if issue.get("state") == "open":
            current = active.get(gap_id)
            number = int(issue.get("number") or 0)
            if current is None or number < int(current.get("number") or 0):
                active[gap_id] = issue
        elif issue.get("state") == "closed":
            completed.add(gap_id)
    return active, completed


def run_loop(
    client: Any,
    repository: str,
    *,
    dry_run: bool = False,
) -> LoopResult:
    """Run one bounded PR-first commercial-readiness orchestration pass."""
    repository = _repository_path(repository)
    pull_requests = _open_pull_requests(client, repository)
    if pull_requests:
        return LoopResult("wait-prs", None, None, pull_requests)

    active, completed = _active_and_completed(_gap_issues(client, repository))
    for gap in COMMERCIAL_GAPS:
        if gap.id in active:
            issue_number = int(active[gap.id].get("number") or 0) or None
            return LoopResult("wait-gap", gap.id, issue_number)

    next_gap = next((gap for gap in COMMERCIAL_GAPS if gap.id not in completed), None)
    if next_gap is None:
        return LoopResult("complete", None, None)
    if dry_run:
        return LoopResult("dispatch-gap", next_gap.id, None)

    _ensure_label(
        client,
        repository,
        COMMERCIAL_LABEL,
        "Autonomous buyer-visible product gap from the commercial-readiness loop.",
    )
    _ensure_label(
        client,
        repository,
        JULES_LABEL,
        "Dispatch this reviewed issue to the Jules coding agent.",
    )
    issue = client.request(
        "POST",
        f"/repos/{repository}/issues",
        {
            "title": next_gap.title,
            "body": render_gap_issue(next_gap),
            "labels": [COMMERCIAL_LABEL],
        },
    )
    issue_number = int((issue or {}).get("number") or 0)
    if issue_number <= 0:
        raise RuntimeError("GitHub did not return a positive issue number")
    client.request(
        "POST",
        f"/repos/{repository}/issues/{issue_number}/labels",
        {"labels": [JULES_LABEL]},
    )
    return LoopResult("dispatch-gap", next_gap.id, issue_number)


def parse_args(argv: list[str]) -> SimpleNamespace:
    """Parse workflow arguments into a stable, test-friendly namespace."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        default=os.getenv("GITHUB_REPOSITORY", ""),
        help="Exact GitHub repository in owner/name form.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parsed = parser.parse_args(argv)
    return SimpleNamespace(repository=parsed.repository, dry_run=parsed.dry_run)


def main(argv: list[str] | None = None) -> int:
    """Execute one scheduled pass and print its JSON decision contract."""
    args = parse_args(os.sys.argv[1:] if argv is None else argv)
    token = (os.getenv("GH_TOKEN") or "").strip()
    if not token:
        raise SystemExit("GH_TOKEN is required")
    result = run_loop(GitHub(token), args.repository, dry_run=args.dry_run)
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
