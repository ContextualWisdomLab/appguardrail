#!/usr/bin/env python3
"""Render an AppGuardrail organization readiness report from GitHub JSON."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from appguardrail_core.org_bundle import OrgBundleError
from appguardrail_core.org_bundle import \
    annotate_missing_pr_repositories as _annotate_missing_pr_repositories
from appguardrail_core.org_bundle import gh_error_message as _gh_error_message
from appguardrail_core.org_bundle import gh_pr_list as _gh_pr_list
from appguardrail_core.org_bundle import gh_repo_list as _gh_repo_list
from appguardrail_core.org_bundle import load_json as _load_json
from appguardrail_core.org_bundle import render_org_evidence
from appguardrail_core.org_bundle import write_bundle as _write_bundle
from appguardrail_core.org_bundle import write_json as _write_json


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default="ContextualWisdomLab")
    parser.add_argument("--repos-json", help="Path to gh repo list JSON output.")
    parser.add_argument("--prs-json", help="Path to gh search prs JSON output.")
    parser.add_argument(
        "--prs-repository",
        help="Repository name to attach to PR JSON rows that do not include repository metadata.",
    )
    parser.add_argument("--out", help="Write markdown report to this path.")
    parser.add_argument(
        "--json-out", help="Write buyer evidence JSON payload to this path."
    )
    parser.add_argument(
        "--bundle-dir",
        help="Write a buyer evidence bundle directory with Markdown, JSON, manifest, and README.",
    )
    parser.add_argument(
        "--generated-at",
        help="Override generated timestamp, primarily for reproducible evidence snapshots.",
    )
    parser.add_argument("--per-repo-pr-limit", type=int, default=100)
    parser.add_argument("--active-repository-target", type=int, default=20)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        repos = (
            _load_json(args.repos_json)
            if args.repos_json
            else _gh_repo_list(args.owner)
        )
        collection_warnings: list[str] = []
        if args.prs_json:
            prs = _load_json(args.prs_json)
        else:
            prs, collection_warnings = _gh_pr_list(
                args.owner, repos, args.per_repo_pr_limit
            )
        if args.prs_repository:
            prs = _annotate_missing_pr_repositories(prs, args.prs_repository)
        generated_at, report, evidence_payload, inventory, pr_summary = (
            render_org_evidence(
                repos,
                prs,
                active_repository_target=args.active_repository_target,
                generated_at=args.generated_at,
            )
        )
    except OrgBundleError as exc:
        raise SystemExit(str(exc)) from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"GitHub command failed: {_gh_error_message(exc)}") from exc

    if args.json_out:
        _write_json(Path(args.json_out), evidence_payload)
    if args.bundle_dir:
        _write_bundle(
            Path(args.bundle_dir),
            report=report,
            evidence_payload=evidence_payload,
            inventory=inventory,
            pr_summary=pr_summary,
            generated_at=generated_at,
            owner=args.owner,
            repos_source=args.repos_json,
            prs_source=args.prs_json,
            prs_repository_override=args.prs_repository,
            per_repo_pr_limit=args.per_repo_pr_limit,
            active_repository_target=args.active_repository_target,
            collection_warnings=collection_warnings,
        )
    if args.out:
        Path(args.out).write_text(report)
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
