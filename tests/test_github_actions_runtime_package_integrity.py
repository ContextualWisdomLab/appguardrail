"""Regression tests for runtime npm package execution in GitHub Actions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


_RULE_ID = "github-actions-runtime-package-without-integrity"


def _scan_workflow(tmp_path: Path, workflow: str) -> list[dict]:
    """Scan one repository-local workflow with production path filtering."""
    workflow_path = tmp_path / ".github" / "workflows" / "security.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_path.write_text(workflow, encoding="utf-8")
    return _scan_file(workflow_path, tmp_path)


def test_runtime_package_rule_is_packaged_and_path_scoped() -> None:
    """The detector must load once and apply only to workflow YAML files."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]

    assert len(matches) == 1
    assert matches[0]["severity"] == "HIGH"
    assert matches[0]["include_paths"] == [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    ]
    assert "CWE-829" in matches[0]["message"]


@pytest.mark.parametrize(
    "command",
    [
        'exec npx -y "$CODEGRAPH_PACKAGE" "$@"',
        "npx --yes @example/scanner@1.2.3 scan .",
        "run: npx -y @example/scanner@1.2.3 scan .",
        "npm exec --yes -- @example/scanner@1.2.3 scan .",
        "npm exec -y -- @example/scanner@1.2.3 scan .",
    ],
)
def test_runtime_registry_package_execution_is_reported(
    tmp_path: Path, command: str
) -> None:
    """Versioned registry packages still lack committed byte integrity."""
    workflow = f"""
name: Security process
on: pull_request
jobs:
  scan:
    steps:
      - name: Prepare CodeGraph CLI
        env:
          CODEGRAPH_PACKAGE: "@colbymchenry/codegraph@0.9.9"
        run: |
          {command}
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert [finding["rule_id"] for finding in findings].count(_RULE_ID) == 1


def test_lock_verified_local_binary_is_not_reported(tmp_path: Path) -> None:
    """A committed lock plus npm ci and local binary execution is safe here."""
    workflow = """
name: Security process
on: pull_request
jobs:
  scan:
    steps:
      - name: Install CodeGraph CLI
        env:
          CODEGRAPH_NO_DOWNLOAD: "1"
        run: |
          npm ci --ignore-scripts --omit=dev --no-audit --no-fund
          node_modules/.bin/codegraph scan .
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _RULE_ID not in {finding["rule_id"] for finding in findings}


def test_runtime_package_text_outside_workflow_is_not_reported(tmp_path: Path) -> None:
    """Documentation and non-workflow YAML must stay outside the rule boundary."""
    example = tmp_path / "docs" / "example.yaml"
    example.parent.mkdir()
    example.write_text("command: npx -y example@1.0.0\n", encoding="utf-8")

    findings = _scan_file(example, tmp_path)

    assert _RULE_ID not in {finding["rule_id"] for finding in findings}


def test_commented_or_echoed_examples_are_not_reported(tmp_path: Path) -> None:
    """Disabled or printed examples must not masquerade as executed commands."""
    workflow = """
name: Documentation example
on: pull_request
jobs:
  docs:
    steps:
      - run: |
          # npx -y example@1.0.0
          echo "npx -y example@1.0.0"
          printf '%s\\n' 'npm exec --yes example@1.0.0'
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _RULE_ID not in {finding["rule_id"] for finding in findings}


def test_repository_workflow_uses_integrity_locked_codegraph() -> None:
    """The retained incident must stay fixed while the detector stays live."""
    repository_root = Path(__file__).parents[1]
    workflow_path = repository_root / ".github/workflows/security-process.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    package_lock = json.loads(
        (
            repository_root
            / "scripts/ci/codegraph-package/package-lock.json"
        ).read_text(encoding="utf-8")
    )
    codegraph_package = package_lock["packages"][
        "node_modules/@colbymchenry/codegraph"
    ]

    findings = _scan_file(workflow_path, repository_root)

    assert _RULE_ID not in {finding["rule_id"] for finding in findings}
    assert "npm ci --ignore-scripts --omit=dev --no-audit --no-fund" in workflow
    assert 'CODEGRAPH_NO_DOWNLOAD: "1"' in workflow
    assert "node_modules/.bin/codegraph" in workflow
    assert codegraph_package["version"] == "0.9.9"
    assert codegraph_package["integrity"].startswith("sha512-")
