"""Organization-level repository and PR readiness summaries."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterable, Mapping

SUPPORTED_PRIMARY_LANGUAGES = {
    "HTML",
    "Java",
    "JavaScript",
    "Python",
    "TypeScript",
}

EXTERNAL_FIRST_LANGUAGES = {
    "C++",
    "Kotlin",
    "R",
    "Rust",
    "Shell",
}

TECHNICAL_CHECK_FAILURES = {
    "action_required",
    "cancelled",
    "error",
    "failure",
    "failed",
    "timed_out",
}

WAITING_CHECK_STATES = {
    "",
    "expected",
    "in_progress",
    "pending",
    "queued",
    "requested",
    "waiting",
}


@dataclass(frozen=True)
class OrgInventory:
    """Repository inventory facts used by product and diligence reports."""

    total_repositories: int
    nonfork_repositories: int
    fork_repositories: int
    private_repositories: int
    supported_nonfork_repositories: int
    unsupported_nonfork_languages: tuple[str, ...]
    primary_language_counts: tuple[tuple[str, int], ...]
    default_branch_counts: tuple[tuple[str, int], ...]
    active_repository_target: int
    active_repository_target_met: bool


@dataclass(frozen=True)
class PullRequestGateSummary:
    """PR gate summary that separates source work from external waiting."""

    total_pull_requests: int
    gate_counts: tuple[tuple[str, int], ...]
    repository_counts: tuple[tuple[str, int], ...]


def build_org_inventory(
    repos: Iterable[Mapping[str, Any]],
    *,
    active_repository_target: int = 20,
) -> OrgInventory:
    """Build a stable organization inventory from GitHub repo JSON."""
    repo_list = list(repos)
    nonforks = [repo for repo in repo_list if not _truthy(repo.get("isFork"))]
    forks = [repo for repo in repo_list if _truthy(repo.get("isFork"))]
    primary_languages = Counter(_primary_language(repo) for repo in repo_list)
    default_branches = Counter(_default_branch(repo) for repo in repo_list)
    unsupported = sorted(
        {
            _primary_language(repo)
            for repo in nonforks
            if _primary_language(repo) not in SUPPORTED_PRIMARY_LANGUAGES
            and _primary_language(repo) != "Unknown"
        }
    )
    supported_nonforks = sum(
        1
        for repo in nonforks
        if _primary_language(repo) in SUPPORTED_PRIMARY_LANGUAGES
    )
    return OrgInventory(
        total_repositories=len(repo_list),
        nonfork_repositories=len(nonforks),
        fork_repositories=len(forks),
        private_repositories=sum(1 for repo in repo_list if _truthy(repo.get("isPrivate"))),
        supported_nonfork_repositories=supported_nonforks,
        unsupported_nonfork_languages=tuple(unsupported),
        primary_language_counts=_sorted_counts(primary_languages),
        default_branch_counts=_sorted_counts(default_branches),
        active_repository_target=active_repository_target,
        active_repository_target_met=len(nonforks) >= active_repository_target,
    )


def summarize_pr_gates(prs: Iterable[Mapping[str, Any]]) -> PullRequestGateSummary:
    """Summarize open PR gates by actionable source work versus external wait."""
    pr_list = list(prs)
    gate_counts = Counter(classify_pr_gate(pr) for pr in pr_list)
    repository_counts = Counter(_pr_repository(pr) for pr in pr_list)
    return PullRequestGateSummary(
        total_pull_requests=len(pr_list),
        gate_counts=_sorted_counts(gate_counts),
        repository_counts=_sorted_counts(repository_counts),
    )


def classify_pr_gate(pr: Mapping[str, Any]) -> str:
    """Classify a PR into the gate that should drive the next action."""
    if _truthy(pr.get("isDraft")):
        return "draft"
    review_decision = str(pr.get("reviewDecision") or "").lower()
    mergeable = str(pr.get("mergeable") or "").lower()
    merge_state = str(pr.get("mergeStateStatus") or "").lower()
    check_states = _check_states(pr)
    if mergeable == "conflicting" or merge_state == "dirty":
        return "source-conflict"
    if review_decision == "changes_requested":
        return "source-review"
    if check_states & TECHNICAL_CHECK_FAILURES:
        return "ci-failure"
    if check_states and check_states <= WAITING_CHECK_STATES:
        return "external-queued"
    if review_decision == "review_required":
        return "review-required"
    if mergeable == "mergeable" and merge_state in {"clean", "has_hooks", "unstable"}:
        return "merge-ready"
    return "needs-triage"


def render_org_readiness_report(
    inventory: OrgInventory,
    pr_summary: PullRequestGateSummary,
    *,
    generated_at: str | None = None,
) -> str:
    """Render a buyer-readable organization readiness report."""
    generated = generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# AppGuardrail Organization Readiness Report",
        "",
        f"Generated: {generated}",
        "",
        "## Repository Inventory",
        "",
        f"- Total repositories: {inventory.total_repositories}",
        f"- Non-fork repositories: {inventory.nonfork_repositories}",
        f"- Fork repositories: {inventory.fork_repositories}",
        f"- Private repositories: {inventory.private_repositories}",
        f"- Supported non-fork primary languages: {inventory.supported_nonfork_repositories}",
        f"- Active repository target: {inventory.active_repository_target}",
        f"- Active repository target met: {_yes_no(inventory.active_repository_target_met)}",
        "",
        "### Primary Languages",
        "",
        *_table("Language", inventory.primary_language_counts),
        "",
        "### Default Branches",
        "",
        *_table("Branch", inventory.default_branch_counts),
        "",
        "## Open PR Gate Summary",
        "",
        f"- Open PRs analyzed: {pr_summary.total_pull_requests}",
        "",
        *_table("Gate", pr_summary.gate_counts),
        "",
        "## Recommendations",
        "",
        *_recommendations(inventory, pr_summary),
        "",
    ]
    return "\n".join(lines).rstrip() + "\n"


def _recommendations(
    inventory: OrgInventory, pr_summary: PullRequestGateSummary
) -> list[str]:
    recommendations: list[str] = []
    if inventory.unsupported_nonfork_languages:
        languages = ", ".join(inventory.unsupported_nonfork_languages)
        recommendations.append(
            f"- Unsupported non-fork primary languages: {languages}. Use external engines first and promote only repeated, precise patterns into built-in rules."
        )
    if inventory.active_repository_target_met:
        recommendations.append(
            "- The organization already meets the active repository count used by the sale-readiness KPI model."
        )
    else:
        recommendations.append(
            "- Active repository coverage is still below the sale-readiness KPI target."
        )
    gate_counts = dict(pr_summary.gate_counts)
    if gate_counts.get("external-queued") or gate_counts.get("review-required"):
        recommendations.append(
            "- Queued checks or review waiting are tracked as external gates, not source defects."
        )
    if gate_counts.get("source-conflict") or gate_counts.get("source-review"):
        recommendations.append(
            "- Source conflicts and change-requested PRs need separate product work before merge."
        )
    if gate_counts.get("ci-failure"):
        recommendations.append(
            "- CI failures should be routed through AppGuardrail IssueOps with redacted logs and deduplicated issue comments."
        )
    return recommendations or ["- No immediate org readiness recommendations."]


def _primary_language(repo: Mapping[str, Any]) -> str:
    language = repo.get("primaryLanguage")
    if isinstance(language, Mapping):
        return str(language.get("name") or "Unknown")
    return str(language or "Unknown")


def _default_branch(repo: Mapping[str, Any]) -> str:
    branch = repo.get("defaultBranchRef")
    if isinstance(branch, Mapping):
        return str(branch.get("name") or "Unknown")
    return str(branch or "Unknown")


def _pr_repository(pr: Mapping[str, Any]) -> str:
    repo = pr.get("repository")
    if isinstance(repo, Mapping):
        return str(repo.get("nameWithOwner") or repo.get("name") or "unknown")
    return str(repo or "unknown")


def _check_states(pr: Mapping[str, Any]) -> set[str]:
    states: set[str] = set()
    for check in pr.get("statusCheckRollup") or ():
        if not isinstance(check, Mapping):
            continue
        value = check.get("conclusion") or check.get("status") or check.get("state")
        states.add(str(value or "").lower())
    return states


def _truthy(value: Any) -> bool:
    return value is True or str(value).lower() in {"1", "true", "yes"}


def _sorted_counts(counter: Counter[str]) -> tuple[tuple[str, int], ...]:
    return tuple(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _table(label: str, rows: tuple[tuple[str, int], ...]) -> list[str]:
    if not rows:
        return [f"| {label} | Count |", "|---|---:|", "| n/a | 0 |"]
    return [f"| {label} | Count |", "|---|---:|", *[f"| {key} | {count} |" for key, count in rows]]


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
