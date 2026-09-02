"""Regression tests for transport-only GitHub Actions polling bounds.

The historical vulnerable/fixed fixtures are answer-free source-code oracles
pinned to the verified ContextualWisdomLab/.github incident in AppGuardrail
issue #1087. Tests execute the packaged production scanner rather than reading
an expected-result field from the fixtures.
"""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


_RULE_ID = "github-actions-transport-only-poll-bound"
_FIXTURES = Path(__file__).parent / "fixtures" / "security_corpus"


def _rule() -> dict:
    """Return the single packaged transport-only polling rule."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1
    return matches[0]


def _scan_workflow(tmp_path: Path, content: str) -> list[dict]:
    """Run production scanning against a workflow-scoped temporary file."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    return _scan_file(workflow, tmp_path)


def _rule_ids(findings: list[dict]) -> list[str]:
    """Return finding identities in scan order."""
    return [finding["rule_id"] for finding in findings]


def test_transport_only_poll_rule_is_packaged_and_workflow_scoped() -> None:
    """The detector must load once and only target GitHub Actions YAML paths."""
    rule = _rule()

    assert rule["severity"] == "HIGH"
    assert rule["extensions"] is None
    assert rule["include_paths"] == [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    ]


def test_verified_vulnerable_control_plane_poll_is_reported(tmp_path: Path) -> None:
    """The protected-predecessor incident must remain a positive regression."""
    content = (
        _FIXTURES / "github_actions_transport_only_poll_vulnerable.yml"
    ).read_text(encoding="utf-8")

    findings = _scan_workflow(tmp_path, content)

    assert _rule_ids(findings).count(_RULE_ID) == 1


def test_protected_wall_clock_repair_is_not_reported(tmp_path: Path) -> None:
    """The causal .github wall-clock repair must remain a fixed oracle."""
    content = (
        _FIXTURES / "github_actions_transport_only_poll_fixed.yml"
    ).read_text(encoding="utf-8")

    findings = _scan_workflow(tmp_path, content)

    assert _RULE_ID not in _rule_ids(findings)


def test_finite_total_attempt_bound_is_not_reported(tmp_path: Path) -> None:
    """A finite total attempt budget bounds successful-no-verdict polling too."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          max_poll_attempts=120
          poll_attempts=0
          while :; do
            poll_attempts=$((poll_attempts + 1))
            if [ "$poll_attempts" -ge "$max_poll_attempts" ]; then
              exit 1
            fi
            reviews="$(gh api repos/example/repo/pulls/1/reviews)"
            [ -n "$reviews" ] && break
            sleep 30
          done
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_explicit_job_timeout_is_a_bounded_negative(tmp_path: Path) -> None:
    """An explicit job wall-clock bound prevents an indefinitely held runner."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - run: |
          max_poll_transport_failures=3
          while true; do
            reviews="$(gh api repos/example/repo/pulls/1/reviews)"
            [ -n "$reviews" ] && break
            sleep 30
          done
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_transport_counter_without_remote_sleeping_poll_is_not_reported(
    tmp_path: Path,
) -> None:
    """A transport counter alone is not the causal resource-retention path."""
    workflow = """
name: One-shot API read
on: workflow_dispatch
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          gh api repos/example/repo
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_comment_only_poll_example_is_not_reported(tmp_path: Path) -> None:
    """Documentation comments must not masquerade as executable polling."""
    workflow = """
name: Docs
on: push
# max_poll_transport_failures=3
# while :; do
#   gh api repos/example/repo
#   sleep 60
# done
jobs:
  docs:
    runs-on: ubuntu-24.04
    steps:
      - run: echo ok
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_rule_respects_workflow_path_scope(tmp_path: Path) -> None:
    """The same shell text outside .github/workflows must not be scanned."""
    content = (
        _FIXTURES / "github_actions_transport_only_poll_vulnerable.yml"
    ).read_text(encoding="utf-8")
    documentation = tmp_path / "docs" / "polling-example.yml"
    documentation.parent.mkdir(parents=True)
    documentation.write_text(content, encoding="utf-8")

    findings = _scan_file(documentation, tmp_path)

    assert _RULE_ID not in _rule_ids(findings)
