#!/usr/bin/env python3
"""Render an AppGuardrail organization readiness report from GitHub JSON."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from appguardrail_core.org_intelligence import (
    build_org_inventory,
    build_buyer_evidence_pack,
    buyer_evidence_pack_to_dict,
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
    parser.add_argument("--json-out", help="Write buyer evidence JSON payload to this path.")
    parser.add_argument("--bundle-dir", help="Write a buyer evidence bundle directory with Markdown, JSON, manifest, and README.")
    parser.add_argument("--generated-at", help="Override generated timestamp, primarily for reproducible evidence snapshots.")
    parser.add_argument("--per-repo-pr-limit", type=int, default=100)
    parser.add_argument("--active-repository-target", type=int, default=20)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repos = _load_json(args.repos_json) if args.repos_json else _gh_repo_list(args.owner)
    collection_warnings: list[str] = []
    if args.prs_json:
        prs = _load_json(args.prs_json)
    else:
        prs, collection_warnings = _gh_pr_list(args.owner, repos, args.per_repo_pr_limit)
    if args.prs_repository:
        prs = _annotate_missing_pr_repositories(prs, args.prs_repository)
    inventory = build_org_inventory(
        repos,
        active_repository_target=args.active_repository_target,
    )
    pr_summary = summarize_pr_gates(prs)
    generated_at = args.generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = render_org_readiness_report(inventory, pr_summary, generated_at=generated_at)
    evidence_payload = buyer_evidence_pack_to_dict(
        build_buyer_evidence_pack(inventory, pr_summary)
    )
    if args.json_out:
        _write_json(Path(args.json_out), evidence_payload)
    if args.bundle_dir:
        _write_bundle(
            Path(args.bundle_dir),
            report=report,
            evidence_payload=evidence_payload,
            inventory=inventory,
            pr_summary=pr_summary,
            args=args,
            generated_at=generated_at,
            collection_warnings=collection_warnings,
        )
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


def _write_bundle(
    bundle_dir: Path,
    *,
    report: str,
    evidence_payload: dict[str, Any],
    inventory: Any,
    pr_summary: Any,
    args: argparse.Namespace,
    generated_at: str,
    collection_warnings: list[str],
) -> None:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "org_readiness_markdown": "org-readiness.md",
        "buyer_evidence_json": "buyer-evidence.json",
        "manifest": "manifest.json",
        "readme": "README.md",
    }
    (bundle_dir / artifacts["org_readiness_markdown"]).write_text(report)
    _write_json(bundle_dir / artifacts["buyer_evidence_json"], evidence_payload)
    manifest = _bundle_manifest(
        artifacts=artifacts,
        evidence_payload=evidence_payload,
        inventory=inventory,
        pr_summary=pr_summary,
        args=args,
        generated_at=generated_at,
        collection_warnings=collection_warnings,
    )
    _write_json(bundle_dir / artifacts["manifest"], manifest)
    (bundle_dir / artifacts["readme"]).write_text(_bundle_readme(manifest))


def _bundle_manifest(
    *,
    artifacts: dict[str, str],
    evidence_payload: dict[str, Any],
    inventory: Any,
    pr_summary: Any,
    args: argparse.Namespace,
    generated_at: str,
    collection_warnings: list[str],
) -> dict[str, Any]:
    action_bucket_counts = dict(pr_summary.action_bucket_counts)
    gate_counts = dict(pr_summary.gate_counts)
    return {
        "generated_at": generated_at,
        "owner": args.owner,
        "collection_warnings": collection_warnings,
        "source": {
            "repositories": _source_descriptor(
                args.repos_json,
                fallback=f"gh repo list {args.owner} --no-archived",
            ),
            "pull_requests": _source_descriptor(
                args.prs_json,
                fallback=f"gh pr list per non-fork repository in {args.owner}",
            ),
            "prs_repository_override": args.prs_repository,
            "per_repo_pr_limit": args.per_repo_pr_limit,
            "active_repository_target": args.active_repository_target,
        },
        "artifacts": artifacts,
        "summary": {
            "total_repositories": inventory.total_repositories,
            "nonfork_repositories": inventory.nonfork_repositories,
            "fork_repositories": inventory.fork_repositories,
            "private_repositories": inventory.private_repositories,
            "supported_nonfork_repositories": inventory.supported_nonfork_repositories,
            "open_pull_requests": pr_summary.total_pull_requests,
            "gate_counts": gate_counts,
            "action_bucket_counts": action_bucket_counts,
            "buyer_evidence_status": evidence_payload["overall_status"],
        },
    }


def _source_descriptor(path: str | None, *, fallback: str) -> dict[str, str]:
    if path:
        return {"kind": "file", "value": path}
    return {"kind": "github_cli", "value": fallback}


def _bundle_readme(manifest: dict[str, Any]) -> str:
    summary = manifest["summary"]
    artifacts = manifest["artifacts"]
    bucket_counts = summary["action_bucket_counts"]
    top_bucket = _top_count(bucket_counts)
    return "\n".join(
        [
            "# AppGuardrail Buyer Evidence Bundle",
            "",
            f"Generated: {manifest['generated_at']}",
            f"Owner: {manifest['owner']}",
            "",
            "## Files",
            "",
            f"- {artifacts['org_readiness_markdown']}: human-readable org readiness report.",
            f"- {artifacts['buyer_evidence_json']}: machine-readable diligence KPI payload.",
            f"- {artifacts['manifest']}: source, artifact, and summary metadata.",
            "",
            "## Current Status",
            "",
            f"- Buyer evidence status: {summary['buyer_evidence_status']}",
            f"- Open PRs analyzed: {summary['open_pull_requests']}",
            f"- Largest action bucket: {top_bucket}",
            "",
            "## How To Use",
            "",
            "1. Start with org-readiness.md for the buyer-facing narrative.",
            "2. Attach buyer-evidence.json to dashboards or diligence data rooms.",
            "3. Use manifest.json to prove the source and generation context.",
            "4. Regenerate the bundle after the 7-day execution plan changes the gates.",
            "",
        ]
    )


def _top_count(counts: dict[str, int]) -> str:
    if not counts:
        return "n/a (0)"
    key, value = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0]
    return f"{key} ({value})"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


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
) -> tuple[list[dict[str, Any]], list[str]]:
    pulls: list[dict[str, Any]] = []
    warnings: list[str] = []
    for repo in repos:
        if repo.get("isFork"):
            continue
        repo_name = repo.get("name")
        if not repo_name:
            continue
        full_name = f"{owner}/{repo_name}"
        try:
            repo_pulls = _gh_json(
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
            )
        except subprocess.CalledProcessError as exc:
            warning = f"Skipped PR collection for {full_name}: {_gh_error_message(exc)}"
            warnings.append(warning)
            print(f"warning: {warning}", file=sys.stderr)
            continue
        for pull in repo_pulls:
            pull["repository"] = {"nameWithOwner": full_name}
            pulls.append(pull)
    return pulls, warnings


def _gh_error_message(exc: subprocess.CalledProcessError) -> str:
    message = (exc.stderr or exc.stdout or str(exc)).strip()
    return " ".join(message.split())


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
