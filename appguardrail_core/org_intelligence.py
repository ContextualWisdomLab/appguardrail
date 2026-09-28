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

GATE_BUCKETS = {
    "ci-failure": "ci-failure",
    "draft": "needs-triage",
    "external-queued": "external-wait",
    "merge-ready": "merge-ready",
    "needs-triage": "needs-triage",
    "review-required": "external-wait",
    "source-conflict": "source-work",
    "source-review": "source-work",
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
class RepositoryGateSummary:
    """One repository's PR gates, normalized into buyer-readable buckets."""

    repository: str
    total: int
    source_work: int
    ci_failures: int
    external_wait: int
    merge_ready: int
    needs_triage: int
    gate_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class PullRequestGateSummary:
    """PR gate summary that separates source work from external waiting."""

    total_pull_requests: int
    gate_counts: tuple[tuple[str, int], ...]
    action_bucket_counts: tuple[tuple[str, int], ...]
    repository_counts: tuple[tuple[str, int], ...]
    top_repositories: tuple[RepositoryGateSummary, ...]


@dataclass(frozen=True)
class BuyerEvidenceMetric:
    """One due-diligence check with beginner-readable status and context."""

    id: str
    label: str
    status: str
    observed: str
    target: str
    detail: str


@dataclass(frozen=True)
class BuyerEvidencePack:
    """Machine-readable buyer evidence derived from org readiness facts."""

    overall_status: str
    metrics: tuple[BuyerEvidenceMetric, ...]
    seven_day_plan: tuple[str, ...]


def build_org_inventory(
    repos: Iterable[Mapping[str, Any]],
    *,
    active_repository_target: int = 20,
) -> OrgInventory:
    """Build a stable organization inventory from GitHub repo JSON."""
    repo_list = list(repos)
    nonforks = []
    forks = []
    primary_languages = Counter()
    default_branches = Counter()
    private_repositories = 0

    for repo in repo_list:
        if _truthy(repo.get("isFork")):
            forks.append(repo)
        else:
            nonforks.append(repo)

        primary_languages[_primary_language(repo)] += 1
        default_branches[_default_branch(repo)] += 1

        if _truthy(repo.get("isPrivate")):
            private_repositories += 1

    unsupported = sorted(
        {
            _primary_language(repo)
            for repo in nonforks
            if _primary_language(repo) not in SUPPORTED_PRIMARY_LANGUAGES
            and _primary_language(repo) != "Unknown"
        }
    )
    supported_nonforks = sum(
        1 for repo in nonforks if _primary_language(repo) in SUPPORTED_PRIMARY_LANGUAGES
    )
    return OrgInventory(
        total_repositories=len(repo_list),
        nonfork_repositories=len(nonforks),
        fork_repositories=len(forks),
        private_repositories=private_repositories,
        supported_nonfork_repositories=supported_nonforks,
        unsupported_nonfork_languages=tuple(unsupported),
        primary_language_counts=_sorted_counts(primary_languages),
        default_branch_counts=_sorted_counts(default_branches),
        active_repository_target=active_repository_target,
        active_repository_target_met=len(nonforks) >= active_repository_target,
    )


def summarize_pr_gates(
    prs: Iterable[Mapping[str, Any]],
    *,
    top_repository_limit: int = 10,
) -> PullRequestGateSummary:
    """Summarize open PR gates by actionable source work versus external wait."""
    pr_list = list(prs)
    classified = [(pr, classify_pr_gate(pr)) for pr in pr_list]
    gate_counts = Counter(gate for _, gate in classified)
    action_counts = Counter(gate_action_bucket(gate) for _, gate in classified)
    repository_counts = Counter(_pr_repository(pr) for pr in pr_list)
    return PullRequestGateSummary(
        total_pull_requests=len(pr_list),
        gate_counts=_sorted_counts(gate_counts),
        action_bucket_counts=_sorted_counts(action_counts),
        repository_counts=_sorted_counts(repository_counts),
        top_repositories=_top_repositories(classified, top_repository_limit),
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


def gate_action_bucket(gate: str) -> str:
    """Map a detailed PR gate to the action bucket shown to beginners."""
    return GATE_BUCKETS.get(gate, "needs-triage")


def build_buyer_evidence_pack(
    inventory: OrgInventory,
    pr_summary: PullRequestGateSummary,
) -> BuyerEvidencePack:
    """Build pass/warn/fail evidence that can be exported for diligence."""
    action_counts = dict(pr_summary.action_bucket_counts)
    total_prs = pr_summary.total_pull_requests
    source_work = action_counts.get("source-work", 0)
    ci_failures = action_counts.get("ci-failure", 0)
    supported_ratio = (
        inventory.supported_nonfork_repositories / inventory.nonfork_repositories
        if inventory.nonfork_repositories
        else 0.0
    )
    source_ratio = source_work / total_prs if total_prs else 0.0
    ci_ratio = ci_failures / total_prs if total_prs else 0.0
    metrics = (
        BuyerEvidenceMetric(
            id="active_repository_coverage",
            label="Active repository coverage",
            status="pass" if inventory.active_repository_target_met else "fail",
            observed=f"{inventory.nonfork_repositories}/{inventory.active_repository_target} non-fork repos",
            target=f">= {inventory.active_repository_target} non-fork repos monitored",
            detail="Shows there is enough live surface area for weekly buyer evidence.",
        ),
        BuyerEvidenceMetric(
            id="supported_language_coverage",
            label="Supported language coverage",
            status=_threshold_status(supported_ratio, pass_at=0.80, warn_at=0.60),
            observed=f"{inventory.supported_nonfork_repositories}/{inventory.nonfork_repositories} non-fork repos ({_percent(supported_ratio)})",
            target=">= 80% pass, >= 60% warn",
            detail="Unsupported languages should start with external engines before built-in rule promotion.",
        ),
        BuyerEvidenceMetric(
            id="source_work_burden",
            label="Source-work burden",
            status=_inverse_threshold_status(source_ratio, pass_at=0.10, warn_at=0.35),
            observed=f"{source_work}/{total_prs} PRs ({_percent(source_ratio)})",
            target="<= 10% pass, <= 35% warn",
            detail="Conflicts and change-requested PRs are product work, not review-process noise.",
        ),
        BuyerEvidenceMetric(
            id="ci_failure_burden",
            label="CI failure burden",
            status=_inverse_threshold_status(ci_ratio, pass_at=0.05, warn_at=0.15),
            observed=f"{ci_failures}/{total_prs} PRs ({_percent(ci_ratio)})",
            target="<= 5% pass, <= 15% warn",
            detail="CI failures should be routed into redacted, deduplicated IssueOps evidence.",
        ),
        BuyerEvidenceMetric(
            id="reusable_evidence_export",
            label="Reusable evidence export",
            status="pass",
            observed="Markdown report and JSON payload",
            target="Human and machine-readable due-diligence output",
            detail="Lets founders, reviewers, and future dashboards consume the same facts.",
        ),
    )
    return BuyerEvidencePack(
        overall_status=_overall_status(metrics),
        metrics=metrics,
        seven_day_plan=tuple(_seven_day_plan(inventory, pr_summary)),
    )


def buyer_evidence_pack_to_dict(pack: BuyerEvidencePack) -> dict[str, Any]:
    """Convert the buyer evidence pack into stable JSON-friendly data."""
    return {
        "overall_status": pack.overall_status,
        "metrics": [
            {
                "id": metric.id,
                "label": metric.label,
                "status": metric.status,
                "observed": metric.observed,
                "target": metric.target,
                "detail": metric.detail,
            }
            for metric in pack.metrics
        ],
        "seven_day_plan": list(pack.seven_day_plan),
    }


def render_org_readiness_report(
    inventory: OrgInventory,
    pr_summary: PullRequestGateSummary,
    *,
    generated_at: str | None = None,
) -> str:
    """Render a buyer-readable organization readiness report."""
    generated = generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    evidence_pack = build_buyer_evidence_pack(inventory, pr_summary)
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
        "## Action Buckets",
        "",
        *_table("Action", pr_summary.action_bucket_counts),
        "",
        "## Top Repositories By Actionable Work",
        "",
        *_repo_gate_table(pr_summary.top_repositories),
        "",
        "## First Actions",
        "",
        *_first_actions(pr_summary),
        "",
        "## Buyer Evidence Pack",
        "",
        f"- Overall status: {evidence_pack.overall_status}",
        "",
        "### Diligence KPI Checks",
        "",
        *_buyer_metric_table(evidence_pack.metrics),
        "",
        "### 7-Day Execution Plan",
        "",
        *[f"- {item}" for item in evidence_pack.seven_day_plan],
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
    """Return narrative recommendations from inventory and PR gate facts."""
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


def _first_actions(pr_summary: PullRequestGateSummary) -> list[str]:
    """Return the first operational actions implied by PR action buckets."""
    action_counts = dict(pr_summary.action_bucket_counts)
    actions: list[str] = []
    if action_counts.get("source-work"):
        actions.append(
            "- Fix source conflicts and change-requested PRs first; those are product work, not queue noise."
        )
    if action_counts.get("ci-failure"):
        actions.append(
            "- Route CI failures through AppGuardrail IssueOps so logs are redacted, compressed, and deduplicated."
        )
    if action_counts.get("external-wait"):
        actions.append(
            "- Track queued checks and review-required PRs as external gates until source work is needed."
        )
    if action_counts.get("merge-ready"):
        actions.append(
            "- Batch merge-ready PRs after confirming no unresolved review threads or source conflicts remain."
        )
    if action_counts.get("needs-triage"):
        actions.append(
            "- Triage unknown or draft PRs before treating them as buyer-ready delivery evidence."
        )
    return actions or ["- No PR actions were found in the supplied data."]


def _seven_day_plan(
    inventory: OrgInventory,
    pr_summary: PullRequestGateSummary,
) -> list[str]:
    """Build a short execution plan from inventory gaps and PR gates."""
    action_counts = dict(pr_summary.action_bucket_counts)
    top_repo = (
        pr_summary.top_repositories[0].repository
        if pr_summary.top_repositories
        else "the highest-risk repository"
    )
    plan: list[str] = []
    if action_counts.get("source-work"):
        plan.append(
            f"Day 1-2: Clear source-work in {top_repo} first, then rerun the report."
        )
    if action_counts.get("ci-failure"):
        plan.append(
            "Day 3: Route CI failures through the security failure collector and attach redacted issue evidence."
        )
    if inventory.unsupported_nonfork_languages:
        languages = ", ".join(inventory.unsupported_nonfork_languages)
        plan.append(
            f"Day 4: Cover {languages} with external-first scans before promoting built-in rules."
        )
    if action_counts.get("external-wait"):
        plan.append(
            "Day 5: Recheck queued checks and review waits; do not count them as source defects unless they fail."
        )
    if action_counts.get("merge-ready"):
        plan.append(
            "Day 6: Batch merge-ready PRs after unresolved review thread and source-conflict checks."
        )
    plan.append(
        "Day 7: Regenerate Markdown and JSON evidence, archive it with the buyer diligence packet."
    )
    return plan


def _primary_language(repo: Mapping[str, Any]) -> str:
    """Extract a repository primary language from GraphQL or flattened JSON."""
    language = repo.get("primaryLanguage")
    if isinstance(language, Mapping):
        return str(language.get("name") or "Unknown")
    return str(language or "Unknown")


def _default_branch(repo: Mapping[str, Any]) -> str:
    """Extract a repository default branch from GraphQL or flattened JSON."""
    branch = repo.get("defaultBranchRef")
    if isinstance(branch, Mapping):
        return str(branch.get("name") or "Unknown")
    return str(branch or "Unknown")


def _pr_repository(pr: Mapping[str, Any]) -> str:
    """Extract a stable repository name from a PR payload."""
    repo = pr.get("repository")
    if isinstance(repo, Mapping):
        return str(repo.get("nameWithOwner") or repo.get("name") or "unknown")
    return str(repo or "unknown")


def _top_repositories(
    classified: list[tuple[Mapping[str, Any], str]],
    limit: int,
) -> tuple[RepositoryGateSummary, ...]:
    """Rank repositories by actionable PR work and return the top entries."""
    by_repo: dict[str, Counter[str]] = {}
    for pr, gate in classified:
        by_repo.setdefault(_pr_repository(pr), Counter())[gate] += 1
    summaries = [
        _repository_gate_summary(repository, gate_counts)
        for repository, gate_counts in by_repo.items()
    ]
    summaries.sort(
        key=lambda item: (
            -item.source_work,
            -item.ci_failures,
            -item.needs_triage,
            -item.total,
            item.repository,
        )
    )
    return tuple(summaries[: max(0, limit)])


def _repository_gate_summary(
    repository: str,
    gate_counts: Counter[str],
) -> RepositoryGateSummary:
    """Convert detailed gate counts for one repository into action buckets."""
    bucket_counts = Counter(
        {
            "source-work": 0,
            "ci-failure": 0,
            "external-wait": 0,
            "merge-ready": 0,
            "needs-triage": 0,
        }
    )
    for gate, count in gate_counts.items():
        bucket_counts[gate_action_bucket(gate)] += count
    return RepositoryGateSummary(
        repository=repository,
        total=sum(gate_counts.values()),
        source_work=bucket_counts["source-work"],
        ci_failures=bucket_counts["ci-failure"],
        external_wait=bucket_counts["external-wait"],
        merge_ready=bucket_counts["merge-ready"],
        needs_triage=bucket_counts["needs-triage"],
        gate_counts=_sorted_counts(gate_counts),
    )


def _check_states(pr: Mapping[str, Any]) -> set[str]:
    """Collect normalized status check states from a PR payload."""
    states: set[str] = set()
    for check in pr.get("statusCheckRollup") or ():
        if not isinstance(check, Mapping):
            continue
        value = check.get("conclusion") or check.get("status") or check.get("state")
        states.add(str(value or "").lower())
    return states


def _truthy(value: Any) -> bool:
    """Interpret GitHub-style boolean fields and truthy strings."""
    return value is True or str(value).lower() in {"1", "true", "yes"}


def _sorted_counts(counter: Counter[str]) -> tuple[tuple[str, int], ...]:
    """Sort count tuples by descending count and then name."""
    return tuple(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _table(label: str, rows: tuple[tuple[str, int], ...]) -> list[str]:
    """Render a two-column Markdown count table."""
    if not rows:
        return [f"| {label} | Count |", "|---|---:|", "| n/a | 0 |"]
    return [
        f"| {label} | Count |",
        "|---|---:|",
        *[f"| {key} | {count} |" for key, count in rows],
    ]


def _repo_gate_table(rows: tuple[RepositoryGateSummary, ...]) -> list[str]:
    """Render repository gate summaries as a Markdown table."""
    header = (
        "| Repository | Open PRs | Source work | CI failures | External wait | Merge ready | Needs triage |",
        "|---|---:|---:|---:|---:|---:|---:|",
    )
    if not rows:
        return [*header, "| n/a | 0 | 0 | 0 | 0 | 0 | 0 |"]
    return [
        *header,
        *[
            f"| {row.repository} | {row.total} | {row.source_work} | {row.ci_failures} | {row.external_wait} | {row.merge_ready} | {row.needs_triage} |"
            for row in rows
        ],
    ]


def _buyer_metric_table(rows: tuple[BuyerEvidenceMetric, ...]) -> list[str]:
    """Render buyer evidence metrics as a Markdown table."""
    header = (
        "| KPI | Status | Observed | Target |",
        "|---|---|---|---|",
    )
    if not rows:
        return [
            *header,
            "| n/a | fail | no evidence | evidence pack should include KPI rows |",
        ]
    return [
        *header,
        *[
            f"| {row.label} | {row.status} | {row.observed} | {row.target} |"
            for row in rows
        ],
    ]


def _threshold_status(value: float, *, pass_at: float, warn_at: float) -> str:
    """Return pass, warn, or fail for metrics where higher is better."""
    if value >= pass_at:
        return "pass"
    if value >= warn_at:
        return "warn"
    return "fail"


def _inverse_threshold_status(value: float, *, pass_at: float, warn_at: float) -> str:
    """Return pass, warn, or fail for metrics where lower is better."""
    if value <= pass_at:
        return "pass"
    if value <= warn_at:
        return "warn"
    return "fail"


def _overall_status(metrics: tuple[BuyerEvidenceMetric, ...]) -> str:
    """Collapse metric statuses into the most severe overall status."""
    statuses = {metric.status for metric in metrics}
    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    return "pass"


def _percent(value: float) -> str:
    """Format a ratio as a one-decimal percentage."""
    return f"{value:.1%}"


def _yes_no(value: bool) -> str:
    """Format a boolean for the Markdown report."""
    return "yes" if value else "no"
