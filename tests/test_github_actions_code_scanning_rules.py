"""Regression tests for repository-local GitHub Actions SARIF coverage rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


_RULE_ID = "github-actions-sarif-missing-pull-request-trigger"


def _rule() -> dict:
    """Return the single packaged rule under test."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1
    return matches[0]


def _matches(text: str) -> bool:
    """Return whether the packaged rule matches workflow text."""
    return bool(_rule()["pattern"].search(text))


def test_code_scanning_coverage_rule_is_packaged_and_path_scoped() -> None:
    """The warning must load once and apply only to workflow YAML files."""
    rule = _rule()

    assert rule["severity"] == "WARNING"
    assert rule["extensions"] is None
    assert rule["include_paths"] == [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    ]


def test_sarif_workflow_without_pull_request_trigger_is_reported() -> None:
    """A local SARIF uploader without any PR entry point must be reported."""
    workflow = """
name: Trivy
on:
  push:
    branches: [develop]
  workflow_dispatch:
jobs:
  scan:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
"""

    assert _matches(workflow)


@pytest.mark.parametrize(
    "on_block",
    [
        "on: pull_request",
        "on: pull_request_target",
        "on: 'pull_request'",
        'on: "pull_request_target"',
        "on: [push, pull_request]",
        "on: {push: {}, pull_request: {}}",
        "on:\n  pull_request:\n  push:",
        "on:\n  'pull_request':\n  push:",
        "'on':\n  pull_request_target:",
        '"on":\n  "pull_request_target":',
    ],
)
def test_sarif_workflow_with_pull_request_coverage_is_not_reported(
    on_block: str,
) -> None:
    """All supported GitHub Actions event syntaxes must satisfy the rule."""
    workflow = f"""
name: Code scanning
{on_block}
jobs:
  scan:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
"""

    assert not _matches(workflow)


def test_quoted_uses_key_still_identifies_sarif_workflow() -> None:
    """Valid quoted YAML keys must not hide an executable SARIF upload step."""
    workflow = """
name: Scorecard
on:
  schedule:
    - cron: '17 3 * * 1'
jobs:
  scan:
    steps:
      - "uses": github/codeql-action/upload-sarif@v3
"""

    assert _matches(workflow)


def test_run_script_text_that_mentions_upload_action_is_not_reported() -> None:
    """Text inside a shell block must not masquerade as an action step."""
    workflow = """
name: Documentation check
on:
  push:
jobs:
  docs:
    steps:
      - run: |
          uses: github/codeql-action/upload-sarif@v3
          echo "example only"
"""

    assert not _matches(workflow)


def test_commented_pull_request_does_not_satisfy_coverage() -> None:
    """A disabled event mentioned only in a comment must still be reported."""
    workflow = """
name: Code scanning
on: [push] # pull_request intentionally disabled
jobs:
  scan:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
"""

    assert _matches(workflow)


def test_central_required_workflow_marker_suppresses_local_warning() -> None:
    """Explicit, reviewed central delegation must suppress the local heuristic."""
    workflow = """
name: Branch-history Trivy
# appguardrail: central-code-scanning
on:
  push:
    branches: [develop]
jobs:
  scan:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
"""

    assert not _matches(workflow)


@pytest.mark.parametrize(
    "marker",
    [
        "# appguardrail: central-code-scanning-extra",
        "# appguardrail: central-code-scanning approved",
        " # appguardrail: central-code-scanning",
    ],
)
def test_near_match_central_marker_does_not_suppress_warning(marker: str) -> None:
    """Only the exact column-zero marker may attest central PR coverage."""
    workflow = f"""
name: Branch-history Trivy
{marker}
on:
  push:
    branches: [develop]
jobs:
  scan:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
"""

    assert _matches(workflow)


def test_delegation_marker_inside_run_block_does_not_suppress_warning() -> None:
    """Shell comments must not masquerade as a file-level delegation marker."""
    workflow = """
name: Branch-history Trivy
on:
  push:
    branches: [develop]
jobs:
  scan:
    steps:
      - run: |
          # appguardrail: central-code-scanning
          echo "not a workflow-level marker"
      - uses: github/codeql-action/upload-sarif@v3
"""

    assert _matches(workflow)


def test_informal_central_workflow_comment_does_not_suppress_warning() -> None:
    """Only the exact auditable delegation marker may suppress the warning."""
    workflow = """
name: Branch-history Trivy
# Central code scanning probably covers pull requests.
on:
  push:
    branches: [develop]
jobs:
  scan:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
"""

    assert _matches(workflow)


def test_reusable_sarif_workflow_is_not_reported() -> None:
    """A workflow_call entry point may inherit PR coverage from its caller."""
    workflow = """
name: Reusable code scanning
on:
  workflow_call:
jobs:
  scan:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
"""

    assert not _matches(workflow)


def test_commented_sarif_action_is_not_reported() -> None:
    """Documentation comments must not be treated as executable SARIF uploads."""
    workflow = """
name: Tests
on:
  push:
jobs:
  test:
    steps:
      # - uses: github/codeql-action/upload-sarif@v3
      - run: pytest
"""

    assert not _matches(workflow)


def test_non_sarif_workflow_is_not_reported() -> None:
    """Ordinary CI workflows must not be mistaken for code-scanning coverage."""
    workflow = """
name: Tests
on:
  push:
jobs:
  test:
    steps:
      - run: pytest
"""

    assert not _matches(workflow)


def test_code_scanning_coverage_rule_respects_workflow_path_scope(
    tmp_path: Path,
) -> None:
    """End-to-end scanning must report the workflow but ignore YAML elsewhere."""
    content = """
name: Scorecard
on:
  schedule:
    - cron: '17 3 * * 1'
jobs:
  scan:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
"""
    workflow = tmp_path / ".github" / "workflows" / "scorecard.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(content, encoding="utf-8")
    documentation = tmp_path / "docs" / "scorecard.yml"
    documentation.parent.mkdir()
    documentation.write_text(content, encoding="utf-8")

    workflow_findings = _scan_file(workflow, tmp_path)
    documentation_findings = _scan_file(documentation, tmp_path)

    assert [finding["rule_id"] for finding in workflow_findings].count(_RULE_ID) == 1
    assert _RULE_ID not in {
        finding["rule_id"] for finding in documentation_findings
    }
