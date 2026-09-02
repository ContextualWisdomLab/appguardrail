"""Regressions for shell break levels in GitHub Actions polling-bound detectors."""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


_HISTORICAL_RULE = "github-actions-transport-only-poll-bound"
_GENERIC_RULE = "github-actions-transport-failure-budget-poll-bound"
_BREAK_ZERO_RULE = "github-actions-poll-invalid-break-zero"


def _scan(tmp_path: Path, content: str) -> list[str]:
    """Scan one temporary workflow through the production scanner."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    return [finding["rule_id"] for finding in _scan_file(workflow, tmp_path)]


def _workflow(*, historical: bool, termination: str) -> str:
    """Build one transport-only polling loop with a selected healthy-path break."""
    counter = "review_poll_failures" if historical else "api_error_streak"
    limit = "max_poll_transport_failures" if historical else "transport_error_budget"
    return f"""
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          {counter}=0
          {limit}=4
          while :; do
            if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
              {counter}=$(({counter} + 1))
              if [ "${counter}" -ge "${limit}" ]; then
                exit 1
              fi
              continue
            fi
            {termination}
            {counter}=0
            sleep 30
          done
"""


def test_historical_break_zero_remains_detectable(tmp_path: Path) -> None:
    """`break 0` is invalid shell syntax and cannot prove successful termination."""
    findings = _scan(tmp_path, _workflow(historical=True, termination="break 0"))
    assert findings.count(_BREAK_ZERO_RULE) == 1


def test_generic_break_zero_remains_detectable(tmp_path: Path) -> None:
    """The renamed family must retain a finding when `break 0` fails to terminate."""
    findings = _scan(tmp_path, _workflow(historical=False, termination="break 0"))
    assert findings.count(_BREAK_ZERO_RULE) == 1


def test_historical_positive_break_level_is_finite(tmp_path: Path) -> None:
    """A positive break level remains accepted as executable loop termination."""
    findings = _scan(tmp_path, _workflow(historical=True, termination="break 1"))
    assert _HISTORICAL_RULE not in findings
    assert _BREAK_ZERO_RULE not in findings


def test_generic_bare_break_is_finite(tmp_path: Path) -> None:
    """A bare break remains accepted as finite healthy-path termination."""
    findings = _scan(tmp_path, _workflow(historical=False, termination="break"))
    assert _GENERIC_RULE not in findings
    assert _BREAK_ZERO_RULE not in findings
