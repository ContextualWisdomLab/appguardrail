from appguardrail_core.org_intelligence import (
    build_org_inventory,
    classify_pr_gate,
    render_org_readiness_report,
    summarize_pr_gates,
)


def test_build_org_inventory_counts_repositories_languages_and_targets():
    repos = [
        {"name": "appguardrail", "isFork": False, "isPrivate": False, "primaryLanguage": {"name": "Python"}, "defaultBranchRef": {"name": "develop"}},
        {"name": "clearfolio", "isFork": False, "isPrivate": False, "primaryLanguage": {"name": "Java"}, "defaultBranchRef": {"name": "main"}},
        {"name": "scopeweave", "isFork": False, "isPrivate": True, "primaryLanguage": {"name": "JavaScript"}, "defaultBranchRef": {"name": "develop"}},
        {"name": "waf-ids-ai-soc", "isFork": False, "isPrivate": False, "primaryLanguage": {"name": "Rust"}, "defaultBranchRef": {"name": "main"}},
        {"name": "html4tree", "isFork": True, "isPrivate": False, "primaryLanguage": {"name": "Kotlin"}, "defaultBranchRef": {"name": "master"}},
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


def test_summarize_pr_gates_and_render_report_include_recommendations():
    repos = [
        {"name": "appguardrail", "isFork": False, "primaryLanguage": {"name": "Python"}, "defaultBranchRef": {"name": "develop"}},
        {"name": "aFIPC", "isFork": False, "primaryLanguage": {"name": "C++"}, "defaultBranchRef": {"name": "master"}},
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
    ]

    inventory = build_org_inventory(repos, active_repository_target=2)
    summary = summarize_pr_gates(prs)
    report = render_org_readiness_report(
        inventory,
        summary,
        generated_at="2026-07-03T00:00:00Z",
    )

    assert summary.total_pull_requests == 2
    assert dict(summary.gate_counts) == {"external-queued": 1, "source-conflict": 1}
    assert "Unsupported non-fork primary languages: C++." in report
    assert "Queued checks or review waiting are tracked as external gates" in report
    assert "Source conflicts and change-requested PRs need separate product work" in report
