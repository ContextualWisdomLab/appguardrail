#!/usr/bin/env python3
"""Repair an interrupted commercial-readiness issue handoff safely."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from types import SimpleNamespace
from typing import Any

from scripts.ci import commercial_readiness_loop as loop


def _label_names(issue: dict[str, Any]) -> frozenset[str]:
    """Return normalized label names from GitHub string or object payloads."""
    names: set[str] = set()
    for label in issue.get("labels") or ():
        if isinstance(label, str) and label:
            names.add(label)
        elif isinstance(label, dict):
            name = label.get("name")
            if isinstance(name, str) and name:
                names.add(name)
    return frozenset(names)


def reconcile_handoff(
    client: Any,
    repository: str,
    *,
    dry_run: bool = False,
) -> loop.LoopResult:
    """Restore the Jules label on one active reviewed gap after partial failure."""
    repository = loop._repository_path(repository)
    pull_requests = loop._open_pull_requests(client, repository)
    if pull_requests:
        return loop.LoopResult("wait-prs", None, None, pull_requests)

    active, _completed = loop._active_and_completed(loop._gap_issues(client, repository))
    for gap in loop.COMMERCIAL_GAPS:
        issue = active.get(gap.id)
        if issue is None:
            continue
        issue_number = int(issue.get("number") or 0)
        if issue_number <= 0:
            raise RuntimeError("active commercial gap has no positive issue number")
        if loop.JULES_LABEL in _label_names(issue):
            return loop.LoopResult("wait-gap", gap.id, issue_number)
        if dry_run:
            return loop.LoopResult("repair-gap", gap.id, issue_number)

        loop._ensure_label(
            client,
            repository,
            loop.JULES_LABEL,
            "Dispatch this reviewed issue to the Jules coding agent.",
        )
        client.request(
            "POST",
            f"/repos/{repository}/issues/{issue_number}/labels",
            {"labels": [loop.JULES_LABEL]},
        )
        return loop.LoopResult("repair-gap", gap.id, issue_number)

    return loop.LoopResult("noop", None, None)


def parse_args(argv: list[str]) -> SimpleNamespace:
    """Parse recovery arguments into a stable, test-friendly namespace."""
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
    """Execute one recovery pass and print its JSON decision contract."""
    args = parse_args(os.sys.argv[1:] if argv is None else argv)
    token = (os.getenv("GH_TOKEN") or "").strip()
    if not token:
        raise SystemExit("GH_TOKEN is required")
    result = reconcile_handoff(loop.GitHub(token), args.repository, dry_run=args.dry_run)
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
