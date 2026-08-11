#!/usr/bin/env python3
"""Validate the active commercial-readiness issue after an interrupted pass.

The hourly workflow invokes OpenCode directly from a trusted registry contract,
so issue labels are no longer an agent handoff mechanism. This compatibility
command is intentionally read-only: it recovers the same validated issue
identity for operators and tests without mutating GitHub state or touching any
review-agent credential.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from types import SimpleNamespace
from typing import Any

from scripts.ci import commercial_readiness_loop as loop


def reconcile_handoff(
    client: Any,
    repository: str,
    *,
    dry_run: bool = False,
) -> loop.LoopResult:
    """Return the current PR-first or validated active-gap state without mutation."""
    del dry_run
    repository = loop._repository_path(repository)
    pull_requests = loop._open_pull_requests(client, repository)
    if pull_requests:
        return loop.LoopResult("wait-prs", None, None, pull_requests)

    active, _completed = loop._active_and_completed(
        loop._gap_issues(client, repository)
    )
    for gap in loop.COMMERCIAL_GAPS:
        issue = active.get(gap.id)
        if issue is None:
            continue
        issue_number = int(issue["number"])
        return loop.LoopResult("wait-gap", gap.id, issue_number)

    return loop.LoopResult("noop", None, None)


def parse_args(argv: list[str]) -> SimpleNamespace:
    """Parse validation arguments into a stable, test-friendly namespace."""
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
    """Execute one read-only validation pass and print its JSON contract."""
    args = parse_args(os.sys.argv[1:] if argv is None else argv)
    token = (os.getenv("GH_TOKEN") or "").strip()
    if not token:
        raise SystemExit("GH_TOKEN is required")
    result = reconcile_handoff(
        loop.GitHub(token),
        args.repository,
        dry_run=args.dry_run,
    )
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
