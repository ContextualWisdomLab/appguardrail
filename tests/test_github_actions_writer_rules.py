"""Structural scanner coverage for write-capable GitHub workflows."""

from __future__ import annotations

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


_PR_TARGET_EXECUTION_RULE_ID = (
    "github-actions-pull-request-target-untrusted-head-execution"
)


def _matches(rule_id: str, workflow: str) -> bool:
    matches = [rule for rule in SCAN_RULES if rule["id"] == rule_id]
    assert len(matches) == 1
    return bool(matches[0]["pattern"].search(workflow))


def _scan_workflow(tmp_path, workflow: str) -> list[dict]:
    """Scan one repository-local workflow through production path filters."""
    workflow_path = tmp_path / ".github" / "workflows" / "review.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(workflow, encoding="utf-8")
    return _scan_file(workflow_path, tmp_path)


def test_pr_target_execution_rule_is_packaged_and_path_scoped() -> None:
    """The detector must load once as a HIGH workflow-only rule."""
    matches = [
        rule for rule in SCAN_RULES if rule["id"] == _PR_TARGET_EXECUTION_RULE_ID
    ]

    assert len(matches) == 1
    assert matches[0]["severity"] == "HIGH"
    assert matches[0]["include_paths"] == [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    ]
    assert "CWE-829" in matches[0]["message"]


def test_privileged_pull_request_target_pr_head_execution_is_reported(
    tmp_path,
) -> None:
    """Same-repository PR heads remain mutable despite an author predicate."""
    workflow = """
name: Privileged review
on: pull_request_target
permissions:
  contents: read
jobs:
  review:
    if: github.event.pull_request.head.repo.full_name == github.repository
    steps:
      - name: Materialize mutable PR head
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - env:
          REVIEW_TOKEN: ${{ secrets.REVIEW_TOKEN }}
        run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


def test_metadata_only_pull_request_target_is_not_reported(tmp_path) -> None:
    """Privileged base-code metadata handling does not execute the PR tree."""
    workflow = """
name: Label trusted metadata
on: pull_request_target
permissions:
  pull-requests: write
jobs:
  label:
    steps:
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: |
            await github.rest.issues.addLabels({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              labels: ["triage"]
            })
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


def test_pr_head_git_worktree_execution_is_reported(tmp_path) -> None:
    """The retained corpus incident used a shell-created PR-head worktree."""
    workflow = """
name: Review in worktree
on: pull_request_target
permissions: {id-token: write}
jobs:
  review:
    env:
      PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}
    steps:
      - run: |
          git fetch origin "$PR_HEAD_SHA"
          git worktree add /tmp/review FETCH_HEAD
          cd /tmp/review
          npx -y @colbymchenry/codegraph@0.9.9 scan .
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


@pytest.mark.parametrize(
    "job_guard",
    [
        "github.event_name == 'repository_dispatch'",
        "github.event_name != 'pull_request_target'",
        "github.event_name == 'repository_dispatch' && github.event.action == 'review'",
    ],
)
def test_job_guard_excluding_pr_target_is_not_reported(
    tmp_path, job_guard: str
) -> None:
    """A shared workflow may isolate execution to a trusted dispatch event."""
    workflow = f"""
on: [pull_request_target, repository_dispatch]
permissions: {{id-token: write}}
jobs:
  review:
    if: {job_guard}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{{{ github.event.client_payload.head_sha || github.event.pull_request.head.sha }}}}
      - run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


def test_block_job_guard_excluding_pr_target_is_not_reported(tmp_path) -> None:
    """Folded job guards retain the same event-reachability semantics."""
    workflow = """
on: [pull_request_target, repository_dispatch]
permissions: {id-token: write}
jobs:
  review:
    if: >-
      always()
      && github.event_name == 'repository_dispatch'
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


def test_top_level_pr_head_env_alias_is_reported(tmp_path) -> None:
    """Workflow env values are available to the shell materialization step."""
    workflow = """
on: pull_request_target
permissions: {id-token: write}
env:
  PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}
jobs:
  review:
    steps:
      - run: |
          git fetch origin "$PR_HEAD_SHA"
          git worktree add /tmp/review FETCH_HEAD
          cd /tmp/review
          npx -y @colbymchenry/codegraph@0.9.9 scan .
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


@pytest.mark.parametrize(
    "workflow",
    [
        """
on: pull_request_target
permissions: {id-token: write}
jobs:
  review:
    steps:
      - uses: example/action@0123456789abcdef0123456789abcdef01234567
        with:
          env:
            PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}
      - run: |
          git fetch origin "$PR_HEAD_SHA"
          bash ./ci/review.sh
""",
        """
on: pull_request_target
permissions: {id-token: write}
jobs:
  review:
    steps:
      - env:
          PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: echo scoped declaration
      - run: |
          git fetch origin "$PR_HEAD_SHA"
          bash ./ci/review.sh
""",
    ],
)
def test_non_job_env_alias_does_not_cross_step_scope(
    tmp_path, workflow: str
) -> None:
    """Action inputs and step-local env do not bind a later shell step."""
    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


def test_checkout_non_ref_pr_expression_is_not_reported(tmp_path) -> None:
    """Only the checkout ref input selects materialized source revision."""
    workflow = """
on: pull_request_target
permissions: {id-token: write}
jobs:
  review:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: main
          path: ${{ github.head_ref }}
      - run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


def test_pr_alias_must_select_git_materialization_revision(tmp_path) -> None:
    """Nearby output cannot bind a trusted git fetch to the PR revision."""
    workflow = """
on: pull_request_target
permissions: {id-token: write}
env:
  PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}
jobs:
  review:
    steps:
      - run: |
          echo "$PR_HEAD_SHA"; git fetch origin main
          bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


def test_bracket_secret_context_grants_job_privilege(tmp_path) -> None:
    """GitHub's bracket context syntax is equivalent to dot syntax."""
    workflow = """
on: pull_request_target
permissions: {contents: read}
jobs:
  review:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - env:
          REVIEW_TOKEN: ${{ secrets['REVIEW_TOKEN'] }}
        run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


@pytest.mark.parametrize(
    "workflow",
    [
        """
on: pull_request
permissions: {id-token: write}
jobs:
  review:
    steps:
      - uses: example/action@0123456789abcdef0123456789abcdef01234567
        with:
          on: pull_request_target
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bash ./ci/review.sh
""",
        """
on: pull_request_target
permissions: {contents: read}
jobs:
  review:
    steps:
      # REVIEW_TOKEN: ${{ secrets.REVIEW_TOKEN }}
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bash ./ci/review.sh
""",
        """
on: pull_request_target
permissions: {contents: read}
jobs:
  review:
    steps:
      - run: |
          cat <<'EXAMPLE'
          permissions: write-all
          EXAMPLE
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bash ./ci/review.sh
""",
    ],
)
def test_yaml_like_inert_text_is_not_causal_privilege_or_trigger(
    tmp_path, workflow: str
) -> None:
    """Action inputs, comments, and run data cannot supply causal authority."""
    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


@pytest.mark.parametrize(
    "workflow",
    [
        """
on:
  - pull_request_target
permissions:
  id-token: write # OIDC exchange
jobs:
  review:
    steps:
      - with:
          ref: ${{ github.event.pull_request.head.sha }}
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: bash ./ci/review.sh
""",
        """
'on':
  pull_request_target:
permissions: {id-token: write} # trusted-base authority
jobs:
  review:
    steps:
      - name: Checkout
        with:
          ref: ${{ github.event.pull_request.head.sha }}
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: ./ci/review.sh
""",
    ],
)
def test_valid_yaml_order_comments_and_trigger_forms_are_reported(
    tmp_path, workflow: str
) -> None:
    """Equivalent YAML syntax must not bypass a HIGH trust-boundary rule."""
    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


@pytest.mark.parametrize(
    "workflow",
    [
        """
on: pull_request
permissions:
  id-token: write
jobs:
  review:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bash ./ci/review.sh
""",
        """
on: pull_request_target
permissions:
  id-token: write
jobs:
  review:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.sha }}
      - run: bash ./ci/review.sh
""",
        """
on: pull_request_target
jobs:
  checkout:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
  publish:
    permissions:
      id-token: write
    steps:
      - run: echo metadata-only
""",
        """
on: pull_request_target
permissions:
  contents: read
jobs:
  review:
    env:
      id-token: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bash ./ci/review.sh
""",
    ],
)
def test_incomplete_pr_target_causal_chains_are_not_reported(
    tmp_path, workflow: str
) -> None:
    """Trigger, trust source, privilege, and execution must share one chain."""
    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


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


def test_write_all_and_spaced_push_reach_scanner_level_mutable_branch_rule(
    tmp_path,
) -> None:
    """The prefilter must admit write-all and shell-valid push whitespace."""
    workflow = tmp_path / ".github" / "workflows" / "repair.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
on: pull_request_target
permissions: write-all
jobs:
  repair:
    steps:
      - run: git  push origin HEAD:${{ github.event.pull_request.head.ref }}
""",
        encoding="utf-8",
    )
    findings = _scan_file(workflow, tmp_path)
    assert [finding["rule_id"] for finding in findings] == [
        "github-actions-mutable-branch-writer"
    ]


@pytest.mark.parametrize(
    "permission",
    [
        'permissions:\n  contents: "write"',
        '"permissions":\n  "contents": \'write\'',
        "permissions: 'write-all'",
        "permissions: {contents: write}",
    ],
)
def test_quoted_write_permission_reaches_mutable_branch_rule(
    tmp_path, permission: str
) -> None:
    """Quoted YAML scalars retain the same repository write authority."""
    workflow = tmp_path / ".github" / "workflows" / "repair.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        f"""
on: pull_request_target
{permission}
jobs:
  repair:
    steps:
      - run: git push origin HEAD:${{{{ github.event.pull_request.head.ref }}}}
""",
        encoding="utf-8",
    )
    findings = _scan_file(workflow, tmp_path)
    assert "github-actions-mutable-branch-writer" in {
        finding["rule_id"] for finding in findings
    }


@pytest.mark.parametrize(
    "permission",
    [
        'permissions:\n  contents: "write"',
        '"permissions":\n  "contents": \'write\'',
        "permissions: 'write-all'",
        "permissions: {contents: write}",
    ],
)
def test_quoted_write_permission_reaches_self_modifying_rule(
    tmp_path, permission: str
) -> None:
    """Quoted authority must not hide a persistent workflow mutation."""
    workflow = tmp_path / ".github" / "workflows" / "self-edit.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        f"""
on: workflow_dispatch
{permission}
jobs:
  retire:
    steps:
      - run: |
          git rm .github/workflows/self-edit.yml
          git commit -m retire
          git push origin HEAD:feature
""",
        encoding="utf-8",
    )
    findings = _scan_file(workflow, tmp_path)
    assert "github-actions-self-modifying-writer" in {
        finding["rule_id"] for finding in findings
    }


def test_comment_only_writer_commands_are_not_reported(tmp_path) -> None:
    """YAML and shell comments are not executable repository mutations."""
    workflow = tmp_path / ".github" / "workflows" / "comments.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
on: workflow_dispatch
permissions:
  contents: write
jobs:
  inspect:
    steps:
      - run: |
          echo read-only
          # git push origin HEAD:${{ github.head_ref }}
          # git rm .github/workflows/comments.yml
          # git commit -m retire
          # git push origin HEAD:feature
""",
        encoding="utf-8",
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(workflow, tmp_path)}
    assert "github-actions-mutable-branch-writer" not in rule_ids
    assert "github-actions-self-modifying-writer" not in rule_ids


def test_continued_mutable_push_is_reported(tmp_path) -> None:
    """A shell line continuation cannot hide an event-derived push target."""
    workflow = tmp_path / ".github" / "workflows" / "continued.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
on: pull_request_target
permissions: {contents: write}
jobs:
  repair:
    steps:
      - run: |
          git push origin \\
            HEAD:${{ github.head_ref }}
""",
        encoding="utf-8",
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(workflow, tmp_path)}
    assert "github-actions-mutable-branch-writer" in rule_ids


def test_indirect_mutable_push_is_reported(tmp_path) -> None:
    """A shell variable cannot hide an event-derived push target."""
    workflow = tmp_path / ".github" / "workflows" / "indirect.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
on: pull_request_target
permissions:
  contents: write
jobs:
  repair:
    steps:
      - run: |
          target=${{ github.head_ref }}
          git push origin HEAD:$target
""",
        encoding="utf-8",
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(workflow, tmp_path)}
    assert "github-actions-mutable-branch-writer" in rule_ids


def test_continued_workflow_mutation_is_reported(tmp_path) -> None:
    """A continued workflow path remains a persistent self-modification."""
    workflow = tmp_path / ".github" / "workflows" / "continued-self.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
on: workflow_dispatch
permissions: {contents: write}
jobs:
  retire:
    steps:
      - run: |
          git rm \\
            .github/workflows/continued-self.yml
          git commit -m retire
          git push origin HEAD:feature
""",
        encoding="utf-8",
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(workflow, tmp_path)}
    assert "github-actions-self-modifying-writer" in rule_ids


def test_non_executable_writer_text_and_protected_ref_are_not_reported(
    tmp_path,
) -> None:
    """Strings, run-body permission text, and protected pushes stay benign."""
    templates = {
        "echo.yml": """
on: workflow_dispatch
permissions: {contents: write}
jobs:
  inspect:
    steps:
      - run: echo "git push origin HEAD:${{ github.head_ref }}"
""",
        "run-permission.yml": """
on: workflow_dispatch
jobs:
  inspect:
    steps:
      - run: |
          contents: write
          git push origin HEAD:${{ github.head_ref }}
""",
        "protected.yml": """
on:
  push:
    branches: [develop]
permissions:
  contents: write
jobs:
  publish:
    steps:
      - run: git push origin HEAD:${{ github.ref_name }}
""",
    }
    for name, text in templates.items():
        workflow = tmp_path / ".github" / "workflows" / name
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text(text, encoding="utf-8")
        rule_ids = {
            finding["rule_id"] for finding in _scan_file(workflow, tmp_path)
        }
        assert "github-actions-mutable-branch-writer" not in rule_ids, name
        assert "github-actions-self-modifying-writer" not in rule_ids, name


def test_variable_whitespace_commit_reaches_scanner_level_self_writer_rule(
    tmp_path,
) -> None:
    """The prefilter must match shell-valid whitespace between git and commit."""
    workflow = tmp_path / ".github" / "workflows" / "self-edit.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
on: workflow_dispatch
permissions: write-all
jobs:
  retire:
    steps:
      - run: |
          git rm .github/workflows/self-edit.yml
          git  commit -m retire
          git  push origin HEAD:feature
""",
        encoding="utf-8",
    )
    findings = _scan_file(workflow, tmp_path)
    assert "github-actions-self-modifying-writer" in {
        finding["rule_id"] for finding in findings
    }


def test_protected_branch_publisher_is_not_a_mutable_branch_writer(tmp_path) -> None:
    """An explicit protected-branch target must not trigger the contributor rule."""
    workflow = tmp_path / ".github" / "workflows" / "publish.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """
on:
  push:
    branches: [develop]
permissions:
  contents: write
jobs:
  publish:
    steps:
      - run: git push origin HEAD:develop
""",
        encoding="utf-8",
    )
    findings = _scan_file(workflow, tmp_path)
    assert "github-actions-mutable-branch-writer" not in {
        finding["rule_id"] for finding in findings
    }


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
