"""Organization evidence bundle helpers shared by CLI and CI scripts."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from appguardrail_core.org_intelligence import (OrgInventory,
                                                PullRequestGateSummary,
                                                build_buyer_evidence_pack,
                                                build_org_inventory,
                                                buyer_evidence_pack_to_dict,
                                                render_org_readiness_report,
                                                summarize_pr_gates)

REPO_FIELDS = "name,isFork,isPrivate,defaultBranchRef,url,description,visibility,primaryLanguage,pushedAt"
PR_DETAIL_FIELDS = "number,title,updatedAt,isDraft,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,headRefName,baseRefName"


class OrgBundleError(RuntimeError):
    """Raised when an organization evidence bundle cannot be produced."""


def load_json(path: str | Path) -> list[dict[str, Any]]:
    """Load a JSON array used as repository or pull-request source data."""
    try:
        payload = json.loads(Path(path).read_text())
    except OSError as exc:
        raise OrgBundleError(f"Cannot read JSON source: {path}") from exc
    except json.JSONDecodeError as exc:
        raise OrgBundleError(f"JSON source is invalid: {exc}") from exc
    if not isinstance(payload, list):
        raise OrgBundleError(f"{path} must contain a JSON array")
    return payload


def annotate_missing_pr_repositories(
    prs: list[dict[str, Any]],
    repository: str,
) -> list[dict[str, Any]]:
    """Attach repository metadata to PR rows that do not already include it."""
    annotated: list[dict[str, Any]] = []
    for pull in prs:
        item = dict(pull)
        item.setdefault("repository", {"nameWithOwner": repository})
        annotated.append(item)
    return annotated


def render_org_evidence(
    repos: list[dict[str, Any]],
    prs: list[dict[str, Any]],
    *,
    active_repository_target: int = 20,
    generated_at: str | None = None,
) -> tuple[str, str, dict[str, Any], OrgInventory, PullRequestGateSummary]:
    """Build the markdown, JSON payload, inventory, and PR summary."""
    inventory = build_org_inventory(
        repos,
        active_repository_target=active_repository_target,
    )
    pr_summary = summarize_pr_gates(prs)
    generated = generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = render_org_readiness_report(
        inventory,
        pr_summary,
        generated_at=generated,
    )
    evidence_payload = buyer_evidence_pack_to_dict(
        build_buyer_evidence_pack(inventory, pr_summary)
    )
    return generated, report, evidence_payload, inventory, pr_summary


def write_bundle(
    bundle_dir: Path,
    *,
    report: str,
    evidence_payload: dict[str, Any],
    inventory: OrgInventory,
    pr_summary: PullRequestGateSummary,
    generated_at: str,
    owner: str,
    repos_source: str | None,
    prs_source: str | None,
    prs_repository_override: str | None = None,
    per_repo_pr_limit: int = 100,
    active_repository_target: int = 20,
    collection_warnings: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """Write the buyer evidence bundle and return its manifest."""
    artifacts = {
        "org_readiness_markdown": "org-readiness.md",
        "buyer_evidence_json": "buyer-evidence.json",
        "manifest": "manifest.json",
        "readme": "README.md",
    }
    manifest = bundle_manifest(
        artifacts=artifacts,
        evidence_payload=evidence_payload,
        inventory=inventory,
        pr_summary=pr_summary,
        generated_at=generated_at,
        owner=owner,
        repos_source=repos_source,
        prs_source=prs_source,
        prs_repository_override=prs_repository_override,
        per_repo_pr_limit=per_repo_pr_limit,
        active_repository_target=active_repository_target,
        collection_warnings=collection_warnings,
    )
    try:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        (bundle_dir / artifacts["org_readiness_markdown"]).write_text(report)
        write_json(bundle_dir / artifacts["buyer_evidence_json"], evidence_payload)
        write_json(bundle_dir / artifacts["manifest"], manifest)
        (bundle_dir / artifacts["readme"]).write_text(bundle_readme(manifest))
    except OSError as exc:
        raise OrgBundleError(
            f"Cannot write buyer evidence bundle: {bundle_dir}"
        ) from exc
    return manifest


def bundle_manifest(
    *,
    artifacts: dict[str, str],
    evidence_payload: dict[str, Any],
    inventory: OrgInventory,
    pr_summary: PullRequestGateSummary,
    generated_at: str,
    owner: str,
    repos_source: str | None,
    prs_source: str | None,
    prs_repository_override: str | None,
    per_repo_pr_limit: int,
    active_repository_target: int,
    collection_warnings: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    """Build manifest metadata for a buyer evidence bundle."""
    return {
        "generated_at": generated_at,
        "owner": owner,
        "collection_warnings": list(collection_warnings),
        "source": {
            "repositories": source_descriptor(
                repos_source,
                fallback=f"gh repo list {owner} --no-archived",
            ),
            "pull_requests": source_descriptor(
                prs_source,
                fallback=f"gh pr list per non-fork repository in {owner}",
            ),
            "prs_repository_override": prs_repository_override,
            "per_repo_pr_limit": per_repo_pr_limit,
            "active_repository_target": active_repository_target,
        },
        "artifacts": artifacts,
        "summary": {
            "total_repositories": inventory.total_repositories,
            "nonfork_repositories": inventory.nonfork_repositories,
            "fork_repositories": inventory.fork_repositories,
            "private_repositories": inventory.private_repositories,
            "supported_nonfork_repositories": inventory.supported_nonfork_repositories,
            "open_pull_requests": pr_summary.total_pull_requests,
            "gate_counts": dict(pr_summary.gate_counts),
            "action_bucket_counts": dict(pr_summary.action_bucket_counts),
            "buyer_evidence_status": evidence_payload["overall_status"],
        },
    }


def source_descriptor(path: str | None, *, fallback: str) -> dict[str, str]:
    """Describe whether evidence came from a local file or live GitHub CLI."""
    if path:
        return {"kind": "file", "value": path}
    return {"kind": "github_cli", "value": fallback}


def bundle_readme(manifest: dict[str, Any]) -> str:
    """Render the beginner-readable bundle README."""
    summary = manifest["summary"]
    artifacts = manifest["artifacts"]
    top_bucket = top_count(summary["action_bucket_counts"])
    warnings = manifest["collection_warnings"]
    warning_line = f"- Collection warnings: {len(warnings)}"
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
            warning_line,
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


def top_count(counts: dict[str, int]) -> str:
    """Return the largest count in a beginner-readable label."""
    if not counts:
        return "n/a (0)"
    key, value = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0]
    return f"{key} ({value})"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write a stable JSON document."""
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def gh_repo_list(owner: str) -> list[dict[str, Any]]:
    """List organization repositories visible to the current gh token."""
    return gh_json(
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


def gh_pr_list(
    owner: str,
    repos: list[dict[str, Any]],
    per_repo_limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Collect open PRs per non-fork repository, preserving repo-level failures."""
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
            repo_pulls = gh_json(
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
            warning = f"Skipped PR collection for {full_name}: {gh_error_message(exc)}"
            warnings.append(warning)
            print(f"warning: {warning}", file=sys.stderr)
            continue
        for pull in repo_pulls:
            pull["repository"] = {"nameWithOwner": full_name}
            pulls.append(pull)
    return pulls, warnings


def gh_json(args: list[str]) -> list[dict[str, Any]]:
    """Run a gh command that returns a JSON array."""
    gh = shutil.which("gh")
    if not gh:
        raise OrgBundleError(
            "gh CLI is required when JSON source files are not provided"
        )
    try:
        result = subprocess.run(  # noqa: S603 - fixed gh command with explicit argv.
            [gh, *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise OrgBundleError("gh command timed out") from exc
    try:
        payload = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise OrgBundleError("gh command returned invalid JSON") from exc
    if not isinstance(payload, list):
        raise OrgBundleError("gh command returned non-array JSON")
    return payload


def gh_error_message(exc: subprocess.CalledProcessError) -> str:
    """Return a compact gh error message suitable for CLI output."""
    message = (exc.stderr or exc.stdout or str(exc)).strip()
    return " ".join(message.split())
