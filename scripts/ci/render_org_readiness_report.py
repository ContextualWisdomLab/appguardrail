#!/usr/bin/env python3
"""Render an AppGuardrail organization readiness report from GitHub JSON."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from appguardrail_core.org_intelligence import (
    build_org_inventory,
    render_org_readiness_report,
    summarize_pr_gates,
)

REPO_FIELDS = "name,isFork,isPrivate,defaultBranchRef,url,description,visibility,primaryLanguage,pushedAt"
PR_DETAIL_FIELDS = "number,title,updatedAt,isDraft,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,headRefName,baseRefName"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default="ContextualWisdomLab")
    parser.add_argument("--repos-json", help="Path to gh repo list JSON output.")
    parser.add_argument("--prs-json", help="Path to gh search prs JSON output.")
    parser.add_argument("--prs-repository", help="Repository name to attach to PR JSON rows that do not include repository metadata.")
    parser.add_argument("--out", help="Write markdown report to this path.")
    parser.add_argument("--per-repo-pr-limit", type=int, default=100)
    parser.add_argument("--active-repository-target", type=int, default=20)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repos = _load_json(args.repos_json) if args.repos_json else _gh_repo_list(args.owner)
    prs = _load_json(args.prs_json) if args.prs_json else _gh_pr_list(args.owner, repos, args.per_repo_pr_limit)
    if args.prs_repository:
        prs = _annotate_missing_pr_repositories(prs, args.prs_repository)
    inventory = build_org_inventory(
        repos,
        active_repository_target=args.active_repository_target,
    )
    pr_summary = summarize_pr_gates(prs)
    report = render_org_readiness_report(inventory, pr_summary)
    if args.out:
        Path(args.out).write_text(report)
    else:
        print(report, end="")
    return 0


def _load_json(path: str) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, list):
        raise SystemExit(f"{path} must contain a JSON array")
    return payload


def _annotate_missing_pr_repositories(
    prs: list[dict[str, Any]],
    repository: str,
) -> list[dict[str, Any]]:
    annotated: list[dict[str, Any]] = []
    for pull in prs:
        item = dict(pull)
        item.setdefault("repository", {"nameWithOwner": repository})
        annotated.append(item)
    return annotated


def _gh_repo_list(owner: str) -> list[dict[str, Any]]:
    return _gh_json(
        [
            "repo",
            "list",
            owner,
            "--no-archived",
            "--limit",
            "200",
            "--json",
            REPO_FIELDS,
        ]
    )


def _gh_pr_list(
    owner: str,
    repos: list[dict[str, Any]],
    per_repo_limit: int,
) -> list[dict[str, Any]]:
    pulls: list[dict[str, Any]] = []
    for repo in repos:
        if repo.get("isFork"):
            continue
        repo_name = repo.get("name")
        if not repo_name:
            continue
        full_name = f"{owner}/{repo_name}"
        for pull in _gh_json(
            [
                "pr",
                "list",
                "--repo",
                full_name,
                "--state",
                "open",
                "--limit",
                str(per_repo_limit),
                "--json",
                PR_DETAIL_FIELDS,
            ]
        ):
            pull["repository"] = {"nameWithOwner": full_name}
            pulls.append(pull)
    return pulls


def _gh_json(args: list[str]) -> list[dict[str, Any]]:
    gh = shutil.which("gh")
    if not gh:
        raise SystemExit("gh CLI is required when --repos-json or --prs-json is not provided")
    result = subprocess.run(  # noqa: S603 - fixed gh command with explicit argv.
        [gh, *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    payload = json.loads(result.stdout or "[]")
    if not isinstance(payload, list):
        raise SystemExit("gh command returned non-array JSON")
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
