from appguardrail_core.org_intelligence import (
    build_buyer_evidence_pack,
    build_org_inventory,
    buyer_evidence_pack_to_dict,
    classify_pr_gate,
    gate_action_bucket,
    render_org_readiness_report,
    summarize_pr_gates,
)


def test_build_org_inventory_counts_repositories_languages_and_targets():
    repos = [
        {
            "name": "appguardrail",
            "isFork": False,
            "isPrivate": False,
            "primaryLanguage": {"name": "Python"},
            "defaultBranchRef": {"name": "develop"},
        },
        {
            "name": "clearfolio",
            "isFork": False,
            "isPrivate": False,
            "primaryLanguage": {"name": "Java"},
            "defaultBranchRef": {"name": "main"},
        },
        {
            "name": "scopeweave",
            "isFork": False,
            "isPrivate": True,
            "primaryLanguage": {"name": "JavaScript"},
            "defaultBranchRef": {"name": "develop"},
        },
        {
            "name": "waf-ids-ai-soc",
            "isFork": False,
            "isPrivate": False,
            "primaryLanguage": {"name": "Rust"},
            "defaultBranchRef": {"name": "main"},
        },
        {
            "name": "html4tree",
            "isFork": True,
            "isPrivate": False,
            "primaryLanguage": {"name": "Kotlin"},
            "defaultBranchRef": {"name": "master"},
        },
    ]

    inventory = build_org_inventory(repos, active_repository_target=4)

    assert inventory.total_repositories == 5
    assert inventory.nonfork_repositories == 4
    assert inventory.fork_repositories == 1
    assert inventory.private_repositories == 1
    assert inventory.supported_nonfork_repositories == 3
    assert inventory.unsupported_nonfork_languages == ("Rust",)
    assert inventory.active_repository_target_met is True
    assert dict(inventory.primary_language_counts)["Python"] == 1
    assert dict(inventory.default_branch_counts)["develop"] == 2


def test_classify_pr_gate_separates_source_work_from_external_waiting():
    queued = {
        "isDraft": False,
        "mergeable": "MERGEABLE",
        "mergeStateStatus": "BLOCKED",
        "reviewDecision": "REVIEW_REQUIRED",
        "statusCheckRollup": [{"status": "QUEUED"}],
    }
    conflict = {
        "isDraft": False,
        "mergeable": "CONFLICTING",
        "mergeStateStatus": "DIRTY",
        "reviewDecision": "",
        "statusCheckRollup": [{"status": "QUEUED"}],
    }
    changes = {
        "isDraft": False,
        "mergeable": "MERGEABLE",
        "mergeStateStatus": "BLOCKED",
        "reviewDecision": "CHANGES_REQUESTED",
        "statusCheckRollup": [{"conclusion": "SUCCESS"}],
    }
    failed = {
        "isDraft": False,
        "mergeable": "MERGEABLE",
        "mergeStateStatus": "BLOCKED",
        "reviewDecision": "",
        "statusCheckRollup": [{"conclusion": "FAILURE"}],
    }

    assert classify_pr_gate(queued) == "external-queued"
    assert classify_pr_gate(conflict) == "source-conflict"
    assert classify_pr_gate(changes) == "source-review"
    assert classify_pr_gate(failed) == "ci-failure"
    assert gate_action_bucket("source-conflict") == "source-work"
    assert gate_action_bucket("source-review") == "source-work"
    assert gate_action_bucket("ci-failure") == "ci-failure"
    assert gate_action_bucket("external-queued") == "external-wait"


def test_summarize_pr_gates_and_render_report_include_recommendations():
    repos = [
        {
            "name": "appguardrail",
            "isFork": False,
            "primaryLanguage": {"name": "Python"},
            "defaultBranchRef": {"name": "develop"},
        },
        {
            "name": "aFIPC",
            "isFork": False,
            "primaryLanguage": {"name": "C++"},
            "defaultBranchRef": {"name": "master"},
        },
    ]
    prs = [
        {
            "repository": {"nameWithOwner": "ContextualWisdomLab/appguardrail"},
            "number": 157,
            "title": "CLI emoji UX improvement",
            "isDraft": False,
            "mergeable": "CONFLICTING",
            "mergeStateStatus": "DIRTY",
            "reviewDecision": "",
            "statusCheckRollup": [{"status": "QUEUED"}],
        },
        {
            "repository": {"nameWithOwner": "ContextualWisdomLab/appguardrail"},
            "number": 160,
            "title": "Queued required workflows",
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "BLOCKED",
            "reviewDecision": "REVIEW_REQUIRED",
            "statusCheckRollup": [{"status": "QUEUED"}],
        },
        {
            "repository": {"nameWithOwner": "ContextualWisdomLab/naruon"},
            "number": 265,
            "title": "Security process failed",
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "BLOCKED",
            "reviewDecision": "",
            "statusCheckRollup": [{"conclusion": "FAILURE"}],
        },
    ]

    inventory = build_org_inventory(repos, active_repository_target=2)
    summary = summarize_pr_gates(prs)
    report = render_org_readiness_report(
        inventory,
        summary,
        generated_at="2026-07-03T00:00:00Z",
    )

    assert summary.total_pull_requests == 3
    assert dict(summary.gate_counts) == {
        "ci-failure": 1,
        "external-queued": 1,
        "source-conflict": 1,
    }
    assert dict(summary.action_bucket_counts) == {
        "ci-failure": 1,
        "external-wait": 1,
        "source-work": 1,
    }
    assert summary.top_repositories[0].repository == "ContextualWisdomLab/appguardrail"
    assert summary.top_repositories[0].source_work == 1
    assert "Unsupported non-fork primary languages: C++." in report
    assert "## First Actions" in report
    assert "Fix source conflicts and change-requested PRs first" in report
    assert "Route CI failures through AppGuardrail IssueOps" in report
    assert "| ContextualWisdomLab/appguardrail | 2 | 1 | 0 | 1 | 0 | 0 |" in report
    assert "Queued checks or review waiting are tracked as external gates" in report
    assert (
        "Source conflicts and change-requested PRs need separate product work" in report
    )


def test_buyer_evidence_pack_adds_kpis_json_and_seven_day_plan():
    repos = [
        {
            "name": "appguardrail",
            "isFork": False,
            "primaryLanguage": {"name": "Python"},
            "defaultBranchRef": {"name": "develop"},
        },
        {
            "name": "clearfolio",
            "isFork": False,
            "primaryLanguage": {"name": "Java"},
            "defaultBranchRef": {"name": "main"},
        },
        {
            "name": "kaefa",
            "isFork": False,
            "primaryLanguage": {"name": "R"},
            "defaultBranchRef": {"name": "develop"},
        },
    ]
    prs = [
        {
            "repository": {"nameWithOwner": "ContextualWisdomLab/appguardrail"},
            "isDraft": False,
            "mergeable": "CONFLICTING",
            "mergeStateStatus": "DIRTY",
            "reviewDecision": "",
            "statusCheckRollup": [],
        },
        {
            "repository": {"nameWithOwner": "ContextualWisdomLab/appguardrail"},
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "BLOCKED",
            "reviewDecision": "CHANGES_REQUESTED",
            "statusCheckRollup": [],
        },
        {
            "repository": {"nameWithOwner": "ContextualWisdomLab/clearfolio"},
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "BLOCKED",
            "reviewDecision": "",
            "statusCheckRollup": [{"conclusion": "FAILURE"}],
        },
        {
            "repository": {"nameWithOwner": "ContextualWisdomLab/clearfolio"},
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "BLOCKED",
            "reviewDecision": "REVIEW_REQUIRED",
            "statusCheckRollup": [{"status": "QUEUED"}],
        },
        {
            "repository": {"nameWithOwner": "ContextualWisdomLab/clearfolio"},
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
            "reviewDecision": "",
            "statusCheckRollup": [{"conclusion": "SUCCESS"}],
        },
    ]

    inventory = build_org_inventory(repos, active_repository_target=3)
    summary = summarize_pr_gates(prs)
    pack = build_buyer_evidence_pack(inventory, summary)
    payload = buyer_evidence_pack_to_dict(pack)
    report = render_org_readiness_report(
        inventory,
        summary,
        generated_at="2026-07-03T00:00:00Z",
    )

    metrics = {metric.id: metric for metric in pack.metrics}
    assert pack.overall_status == "fail"
    assert metrics["active_repository_coverage"].status == "pass"
    assert metrics["supported_language_coverage"].status == "warn"
    assert metrics["source_work_burden"].status == "fail"
    assert metrics["ci_failure_burden"].status == "fail"
    assert payload["overall_status"] == "fail"
    assert payload["metrics"][0]["id"] == "active_repository_coverage"
    assert payload["seven_day_plan"][-1].startswith("Day 7:")
    assert "## Buyer Evidence Pack" in report
    assert (
        "| Source-work burden | fail | 2/5 PRs (40.0%) | <= 10% pass, <= 35% warn |"
        in report
    )
    assert (
        "Day 1-2: Clear source-work in ContextualWisdomLab/appguardrail first" in report
    )
