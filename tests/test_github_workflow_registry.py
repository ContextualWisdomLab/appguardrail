"""Regression contract for source-bound GitHub workflow registry evidence."""

from appguardrail_core.github_workflow_registry import build_workflow_inventory


def test_active_registry_entry_missing_from_exact_tree_is_orphaned() -> None:
    """An active workflow absent from the protected branch tree must not be clean."""
    branch_sha = "a" * 40
    tree_sha = "b" * 40
    inventory = build_workflow_inventory(
        repository="ContextualWisdomLab/appguardrail",
        verified_at="2026-08-15T14:00:00Z",
        repository_payload={
            "full_name": "ContextualWisdomLab/appguardrail",
            "default_branch": "develop",
        },
        branch_payload={
            "name": "develop",
            "protected": True,
            "commit": {
                "sha": branch_sha,
                "commit": {"tree": {"sha": tree_sha}},
            },
        },
        tree_payload={"sha": tree_sha, "truncated": False, "tree": []},
        workflow_pages=[
            {
                "total_count": 1,
                "workflows": [
                    {
                        "id": 327745139,
                        "name": "Apply dashboard pluralization once",
                        "path": ".github/workflows/apply-dashboard-pluralization-once.yml",
                        "state": "active",
                        "html_url": "https://github.com/ContextualWisdomLab/appguardrail/actions/workflows/327745139",
                    }
                ],
            }
        ],
    )

    assert inventory.complete is True
    assert inventory.entries[0].status == "orphaned_deleted"
    assert inventory.entries[0].workflow_id == 327745139
