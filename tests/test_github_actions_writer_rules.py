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


def test_negated_other_event_guard_does_not_exclude_pr_target(tmp_path) -> None:
    """Negating a trusted-event equality admits PR-target execution."""
    workflow = """
on: [pull_request_target, repository_dispatch]
permissions: {id-token: write}
jobs:
  review:
    if: ${{ !(github.event_name == 'repository_dispatch') }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


def test_boolean_inverted_other_event_guard_does_not_exclude_pr_target(
    tmp_path,
) -> None:
    """Comparing a trusted-event predicate to false admits PR-target."""
    workflow = """
on: [pull_request_target, repository_dispatch]
permissions: {id-token: write}
jobs:
  review:
    if: (github.event_name == 'repository_dispatch') == false
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


def test_or_of_non_pr_target_events_is_not_reported(tmp_path) -> None:
    """Every disjunct excludes PR-target, so the job is unreachable there."""
    workflow = """
on: [pull_request_target, repository_dispatch, workflow_dispatch]
permissions: {id-token: write}
jobs:
  review:
    if: github.event_name == 'repository_dispatch' || github.event_name == 'workflow_dispatch'
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


def test_safe_event_guard_with_unrelated_negation_is_not_reported(tmp_path) -> None:
    """An independent cancelled predicate cannot reopen PR-target reachability."""
    workflow = """
on: [pull_request_target, repository_dispatch]
permissions: {id-token: write}
jobs:
  review:
    if: github.event_name != 'pull_request_target' && !cancelled()
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


@pytest.mark.parametrize(
    "head_expression",
    [
        "github['event']['pull_request']['head']['sha']",
        "github.event.pull_request.head['sha']",
        "github['head_ref']",
    ],
)
def test_bracket_pr_head_expression_is_reported(
    tmp_path, head_expression: str
) -> None:
    """GitHub expression index and dot paths have identical trust semantics."""
    workflow = f"""
on: pull_request_target
permissions: {{id-token: write}}
jobs:
  review:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{{{ {head_expression} }}}}
      - run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


@pytest.mark.parametrize("global_field", ["permissions: write-all", "env:\n  PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}"])
def test_top_level_authority_after_jobs_is_reported(
    tmp_path, global_field: str
) -> None:
    """Top-level YAML field order does not change authority or aliases."""
    privilege = "" if global_field.startswith("permissions") else "permissions: write-all\n"
    ref = (
        "${{ github.event.pull_request.head.sha }}"
        if global_field.startswith("permissions")
        else '"$PR_HEAD_SHA"'
    )
    workflow = f"""
on: pull_request_target
{privilege}jobs:
  review:
    steps:
      - run: |
          git checkout {ref}
          bash ./ci/review.sh
{global_field}
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


@pytest.mark.parametrize(
    "step",
    [
        """      - env:
          PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          git checkout \"$PR_HEAD_SHA\"
          bash ./ci/review.sh""",
        """      - name: Review
        env:
          PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          git checkout \"$PR_HEAD_SHA\"
          bash ./ci/review.sh""",
    ],
)
def test_same_step_pr_head_env_alias_is_reported(tmp_path, step: str) -> None:
    """A step-local alias is live in that same step's shell."""
    workflow = f"""
on: pull_request_target
permissions: {{id-token: write}}
jobs:
  review:
    steps:
{step}
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


@pytest.mark.parametrize(
    "env_location",
    [
        "env: {PR_HEAD_SHA: \"${{ github.event.pull_request.head.sha }}\"}\n",
        """jobs:
  review:
    env: {PR_HEAD_SHA: "${{ github.event.pull_request.head.sha }}"}
    steps:
      - run: |
          git checkout "$PR_HEAD_SHA"
          bash ./ci/review.sh
""",
        """jobs:
  review:
    steps:
      - env: {PR_HEAD_SHA: "${{ github.event.pull_request.head.sha }}"}
        run: |
          git checkout "$PR_HEAD_SHA"
          bash ./ci/review.sh
""",
    ],
)
def test_flow_env_pr_head_alias_is_reported(tmp_path, env_location: str) -> None:
    """Flow and block env mappings have the same one-hop alias semantics."""
    if env_location.startswith("env:"):
        body = f"""{env_location}jobs:
  review:
    steps:
      - run: |
          git checkout "$PR_HEAD_SHA"
          bash ./ci/review.sh
"""
    else:
        body = env_location
    workflow = f"""
on: pull_request_target
permissions: {{id-token: write}}
{body}"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


def test_inline_checkout_ref_is_reported(tmp_path) -> None:
    """A flow-style with.ref still selects the mutable PR revision."""
    workflow = """
on: pull_request_target
permissions: {id-token: write}
jobs:
  review:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
      - run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


@pytest.mark.parametrize(
    "mapping",
    [
        """env: {
  PR_HEAD_SHA: "${{ github.event.pull_request.head.sha }}"
}
jobs:
  review:
    steps:
      - run: |
          git checkout "$PR_HEAD_SHA"
          bash ./ci/review.sh
""",
        """jobs:
  review:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with: {
          ref: "${{ github.event.pull_request.head.sha }}"
        }
      - run: bash ./ci/review.sh
""",
    ],
)
def test_multiline_flow_mapping_is_reported(tmp_path, mapping: str) -> None:
    """Multiline and single-line flow mappings have equivalent semantics."""
    workflow = f"""
on: pull_request_target
permissions: {{id-token: write}}
{mapping}"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


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


def test_checkout_sibling_ref_is_not_reported(tmp_path) -> None:
    """Only with.ref, not an env key named ref, controls checkout revision."""
    workflow = """
on: pull_request_target
permissions: {id-token: write}
jobs:
  review:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        env:
          ref: ${{ github.event.pull_request.head.sha }}
        with:
          ref: main
      - run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


@pytest.mark.parametrize(
    "materialization",
    [
        'git fetch origin "$PR_HEAD_SHA"',
        'git fetch origin main # "$PR_HEAD_SHA" is retained for logs',
    ],
)
def test_fetch_without_pr_tree_selection_is_not_reported(
    tmp_path, materialization: str
) -> None:
    """Fetching alone does not make a later trusted-base script PR code."""
    workflow = f"""
on: pull_request_target
permissions: {{id-token: write}}
env:
  PR_HEAD_SHA: ${{{{ github.event.pull_request.head.sha }}}}
jobs:
  review:
    steps:
      - run: |
          {materialization}
          bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


def test_worktree_without_execution_link_is_not_reported(tmp_path) -> None:
    """A later scalar command still runs in the trusted base workspace."""
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
      - run: bash ./ci/base.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


@pytest.mark.parametrize(
    "execution",
    [
        "bash /tmp/review/ci/review.sh",
        "pushd /tmp/review\nbash ./ci/review.sh",
    ],
)
def test_worktree_linked_block_execution_is_reported(
    tmp_path, execution: str
) -> None:
    """Absolute paths and pushd both bind execution to the PR worktree."""
    indented_execution = execution.replace("\n", "\n          ")
    workflow = f"""
on: pull_request_target
permissions: {{id-token: write}}
env:
  PR_HEAD_SHA: ${{{{ github.event.pull_request.head.sha }}}}
jobs:
  review:
    steps:
      - run: |
          git fetch origin "$PR_HEAD_SHA"
          git worktree add /tmp/review FETCH_HEAD
          {indented_execution}
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


def test_worktree_working_directory_execution_is_reported(tmp_path) -> None:
    """A later step may explicitly run inside the selected PR worktree."""
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
      - working-directory: /tmp/review
        run: bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


def test_trusted_fetch_overwrites_pr_fetch_head(tmp_path) -> None:
    """The most recent ordinary fetch determines FETCH_HEAD selection."""
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
          git fetch origin main
          git worktree add /tmp/review FETCH_HEAD
          cd /tmp/review
          bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


@pytest.mark.parametrize("option", ["--no-write-fetch-head", "--append"])
def test_non_overwriting_fetch_preserves_pr_fetch_head(
    tmp_path, option: str
) -> None:
    """Fetch modes that do not replace FETCH_HEAD preserve PR provenance."""
    workflow = f"""
on: pull_request_target
permissions: {{id-token: write}}
env:
  PR_HEAD_SHA: ${{{{ github.event.pull_request.head.sha }}}}
jobs:
  review:
    steps:
      - run: |
          git fetch origin "$PR_HEAD_SHA"
          git fetch {option} origin main
          git worktree add /tmp/review FETCH_HEAD
          cd /tmp/review
          bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


@pytest.mark.parametrize(
    "selection",
    [
        """      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: main
      - run: bash ./ci/base.sh""",
        """      - run: |
          git checkout "${{ github.event.pull_request.head.sha }}"
          git checkout main
          bash ./ci/base.sh""",
    ],
)
def test_later_trusted_selection_invalidates_pr_tree(
    tmp_path, selection: str
) -> None:
    """Execution provenance follows the most recent selected workspace tree."""
    workflow = f"""
on: pull_request_target
permissions: {{id-token: write}}
jobs:
  review:
    steps:
{selection}
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


@pytest.mark.parametrize(
    "execution",
    [
        "bash ./ci/base.sh --output /tmp/review/results.json",
        "cd /tmp/review\ncd \"$GITHUB_WORKSPACE\"\nbash ./ci/base.sh",
    ],
)
def test_worktree_path_mention_or_exit_is_not_reported(
    tmp_path, execution: str
) -> None:
    """Arguments and exited directories do not prove PR-tree execution."""
    body = execution.replace("\n", "\n          ")
    workflow = f"""
on: pull_request_target
permissions: {{id-token: write}}
env:
  PR_HEAD_SHA: ${{{{ github.event.pull_request.head.sha }}}}
jobs:
  review:
    steps:
      - run: |
          git fetch origin "$PR_HEAD_SHA"
          git worktree add /tmp/review FETCH_HEAD
          {body}
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _PR_TARGET_EXECUTION_RULE_ID not in {
        finding["rule_id"] for finding in findings
    }


def test_normalized_relative_worktree_entry_is_reported(tmp_path) -> None:
    """Equivalent relative path spellings bind the same worktree."""
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
          git worktree add ./review FETCH_HEAD
          cd review
          bash ./ci/review.sh
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(
        _PR_TARGET_EXECUTION_RULE_ID
    ) == 1


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
