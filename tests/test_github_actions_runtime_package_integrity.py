"""Regression tests for runtime npm package execution in GitHub Actions."""

from __future__ import annotations

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
        'npx --yes "$CODEGRAPH_PACKAGE" scan .',
        'npm exec --package="$CODEGRAPH_PACKAGE" --yes -- scan .',
        'npm exec -y -- "$CODEGRAPH_PACKAGE" scan .',
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


@pytest.mark.parametrize(
    "package_value, command",
    [
        (None, "npx -y eslint ."),
        (None, "npm exec --yes -- eslint ."),
        ("./tools/local-cli.tgz", 'npx -y "$TOOL_PACKAGE" scan .'),
    ],
)
def test_local_or_unbound_package_execution_is_not_reported(
    tmp_path: Path, package_value: str | None, command: str
) -> None:
    """Local tools without a versioned registry binding stay outside scope."""
    env = (
        f'        env:\n          TOOL_PACKAGE: "{package_value}"\n'
        if package_value
        else ""
    )
    workflow = f"""
name: Local tool
on: pull_request
jobs:
  scan:
    steps:
      - name: Run local tool
{env}        run: |
          npm ci --ignore-scripts
          {command}
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
          cat <<'EXAMPLE'
          npx -y example@1.0.0
          EXAMPLE
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _RULE_ID not in {finding["rule_id"] for finding in findings}


@pytest.mark.parametrize(
    "workflow",
    [
        """
name: Cross-step variable
on: pull_request
jobs:
  scan:
    steps:
      - name: Declare package
        env:
          TOOL_PACKAGE: "example-tool@1.0.0"
        run: echo "declaration only"
      - name: Undefined variable in another step
        run: npx -y "$TOOL_PACKAGE"
""",
        """
name: Quoted heredoc documentation
on: pull_request
jobs:
  scan:
    steps:
      - name: Print documentation
        env:
          TOOL_PACKAGE: "example-tool@1.0.0"
        run: |
          cat <<'EXAMPLE'
          npx -y "$TOOL_PACKAGE"
          EXAMPLE
""",
        """
name: Variable is not the package selector
on: pull_request
jobs:
  scan:
    steps:
      - name: Label a local report
        env:
          TOOL_PACKAGE: "example-tool@1.0.0"
        run: npx -y local-report --label "$TOOL_PACKAGE"
""",
        """
name: Variable prefix collision
on: pull_request
jobs:
  scan:
    steps:
      - name: Run a different package variable
        env:
          TOOL_PACKAGE: "example-tool@1.0.0"
        run: npx -y "$TOOL_PACKAGE_SUFFIX"
""",
    ],
)
def test_noncausal_runtime_package_text_is_not_reported(
    tmp_path: Path, workflow: str
) -> None:
    """Lexical proximity must not replace step-local package binding."""
    findings = _scan_workflow(tmp_path, workflow)

    assert _RULE_ID not in {finding["rule_id"] for finding in findings}


def test_repository_workflow_remains_a_positive_incident_fixture() -> None:
    """The protected incident remains detected until canonical consumption exists."""
    repository_root = Path(__file__).parents[1]
    workflow_path = repository_root / ".github/workflows/security-process.yml"

    findings = _scan_file(workflow_path, repository_root)

    assert [finding["rule_id"] for finding in findings].count(_RULE_ID) == 1
