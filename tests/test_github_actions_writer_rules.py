"""Structural scanner coverage for write-capable GitHub workflows."""

from __future__ import annotations

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


def _matches(rule_id: str, workflow: str) -> bool:
    matches = [rule for rule in SCAN_RULES if rule["id"] == rule_id]
    assert len(matches) == 1
    return bool(matches[0]["pattern"].search(workflow))


def test_mutable_contributor_branch_writer_is_reported() -> None:
    workflow = """
on: pull_request_target
permissions:
  contents: write
jobs:
  repair:
    steps:
      - run: git push origin HEAD:${{ github.event.pull_request.head.ref }}
"""
    assert _matches("github-actions-mutable-branch-writer", workflow)


def test_self_deleting_workflow_is_reported_despite_benign_name() -> None:
    workflow = """
name: Documentation helper
on: workflow_dispatch
permissions:
  contents: write
jobs:
  docs:
    steps:
      - run: |
          git rm .github/workflows/docs-helper.yml
          git commit -m cleanup
          git push origin HEAD
"""
    assert _matches("github-actions-self-modifying-writer", workflow)


def test_write_all_reaches_scanner_level_mutable_branch_rule(tmp_path) -> None:
    """The scanner prefilter must not discard GitHub's write-all shorthand."""
    workflow = tmp_path / ".github" / "workflows" / "repair.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
on: pull_request_target
permissions: write-all
jobs:
  repair:
    steps:
      - run: git push origin HEAD:${{ github.event.pull_request.head.ref }}
""",
        encoding="utf-8",
    )
    findings = _scan_file(workflow, tmp_path)
    assert [finding["rule_id"] for finding in findings] == [
        "github-actions-mutable-branch-writer"
    ]


def test_non_persistent_workflow_file_operations_are_not_reported() -> None:
    """Read-only and uncommitted workspace cleanup are not repository writes."""
    templates = (
        "sed -n '1,20p' .github/workflows/ci.yml",
        "git rm .github/workflows/copied.yml",
        "rm -rf snapshot/.github/workflows/",
    )
    for command in templates:
        workflow = f"""
on: workflow_dispatch
permissions:
  contents: write
jobs:
  inspect:
    steps:
      - run: {command}
"""
        assert not _matches("github-actions-self-modifying-writer", workflow)


def test_read_only_diagnostic_and_protected_release_are_not_reported() -> None:
    diagnostic = """
on: pull_request
permissions:
  contents: read
jobs:
  inspect:
    steps:
      - run: git status
"""
    release = """
on:
  push:
    tags: ['v*']
permissions:
  contents: write
jobs:
  publish:
    steps:
      - run: gh release create "${{ github.ref_name }}"
"""
    for text in (diagnostic, release):
        assert not _matches("github-actions-mutable-branch-writer", text)
        assert not _matches("github-actions-self-modifying-writer", text)
