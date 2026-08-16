"""Source-authoritative regressions for GitHub Actions workflow-input injection."""

from __future__ import annotations

import hashlib
import textwrap
from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "github-actions-workflow-input-command-injection"
_SOURCE_REPOSITORY = "ContextualWisdomLab/.github"
_VULNERABLE_HEAD_SHA = "2b034ac27d90487b4b0df3aea9d3fdc355e97296"
_VULNERABLE_BLOB_SHA = "f86b614022a658702ce3c6032ff61ffe4658adde"
_FIXED_HEAD_SHA = "5999b2bdbd32a362b01b8553f1ee2a1d7f45e5da"
_FIXED_BLOB_SHA = "118816bd7156472baa0cc011cd6e8a4d68b7ff22"
_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_VULNERABLE_FIXTURE = _FIXTURE_DIR / "github_actions_deploy_pages_vulnerable.yml"
_FIXED_FIXTURE = _FIXTURE_DIR / "github_actions_deploy_pages_fixed.yml"


def _git_blob_sha(path: Path) -> str:
    """Return the immutable Git object identity for one source fixture."""
    payload = path.read_bytes()
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _rule() -> dict:
    """Return the single packaged workflow-input injection detector."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path, *, name: str = "deploy-pages.yml") -> list[dict]:
    """Execute the production scanner and isolate this detector's findings."""
    source_file = tmp_path / ".github" / "workflows" / name
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def _workflow(body: str, *, trigger: str = "workflow_call", input_type: str = "string") -> str:
    """Build one reusable or manually dispatched workflow around a test body."""
    return textwrap.dedent(
        f"""
        name: Injection contract
        on:
          {trigger}:
            inputs:
              release_name:
                description: Caller-controlled release label
                required: true
                type: {input_type}
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - name: Publish
        {textwrap.indent(textwrap.dedent(body).strip(), "        ")}
        """
    ).lstrip()


def test_source_provenance_is_exact_and_immutable() -> None:
    """Pin the vulnerable and reviewed fixed central-workflow Git objects."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/.github"
    assert _VULNERABLE_HEAD_SHA == "2b034ac27d90487b4b0df3aea9d3fdc355e97296"
    assert _FIXED_HEAD_SHA == "5999b2bdbd32a362b01b8553f1ee2a1d7f45e5da"
    assert _git_blob_sha(_VULNERABLE_FIXTURE) == _VULNERABLE_BLOB_SHA
    assert _git_blob_sha(_FIXED_FIXTURE) == _FIXED_BLOB_SHA


def test_packaged_rule_detects_exact_central_workflow_regression() -> None:
    """Detect direct string-input interpolation in the collected shell block."""
    rule = _rule()
    source = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")

    assert rule["severity"] == "CRITICAL"
    assert rule["pattern"].search(source)


def test_packaged_rule_declares_bounded_workflow_prefilters() -> None:
    """Skip multiline evaluation outside input-bearing workflow source."""
    assert _rule()["required_substrings"] == (
        "workflow_",
        "inputs",
        "type: string",
        "run:",
        "${{",
    )


def test_packaged_rule_ignores_exact_reviewed_fix() -> None:
    """Keep validated env indirection and shell-native expansion clean."""
    source = _FIXED_FIXTURE.read_text(encoding="utf-8")
    assert not _rule()["pattern"].search(source)


def test_packaged_rule_detects_inline_run_interpolation() -> None:
    """Detect a string input embedded in a one-line shell program."""
    source = _workflow(
        """
          run: echo "${{ inputs.release_name }}"
        """
    )
    assert _rule()["pattern"].search(source)


def test_packaged_rule_detects_folded_run_and_bracket_input() -> None:
    """Detect folded shell source and bracket-style input access."""
    source = _workflow(
        """
          run: >
            printf '%s'
            "${{ inputs['release_name'] }}"
        """
    )
    assert _rule()["pattern"].search(source)


def test_packaged_rule_detects_workflow_dispatch_string_input() -> None:
    """Apply the same command boundary to manually supplied string inputs."""
    source = _workflow(
        """
          run: git tag "${{ inputs.release_name }}"
        """,
        trigger="workflow_dispatch",
    )
    assert _rule()["pattern"].search(source)


def test_packaged_rule_detects_expression_with_fallback() -> None:
    """Do not let expression operators hide the caller-controlled input."""
    source = _workflow(
        """
          run: echo "${{ inputs.release_name || '(none)' }}"
        """
    )
    assert _rule()["pattern"].search(source)


def test_packaged_rule_ignores_env_indirection() -> None:
    """Accept expression evaluation into env followed by native shell quoting."""
    source = _workflow(
        """
          env:
            RELEASE_NAME: ${{ inputs.release_name }}
          run: |
            printf '%s\n' "${RELEASE_NAME}"
        """
    )
    assert not _rule()["pattern"].search(source)


def test_packaged_rule_ignores_action_with_input() -> None:
    """Do not classify an action input as inline shell source."""
    source = _workflow(
        """
          uses: vendor/publisher@0123456789abcdef0123456789abcdef01234567
          with:
            release-name: ${{ inputs.release_name }}
        """
    )
    assert not _rule()["pattern"].search(source)


def test_packaged_rule_ignores_expression_outside_run() -> None:
    """Do not report display names and conditions as shell interpolation."""
    source = _workflow(
        """
          name: Publish ${{ inputs.release_name }}
          if: ${{ inputs.release_name != '' }}
          run: echo "constant"
        """
    )
    assert not _rule()["pattern"].search(source)


def test_packaged_rule_ignores_non_string_input() -> None:
    """Avoid reporting typed boolean inputs that cannot carry shell syntax."""
    source = _workflow(
        """
          run: echo "${{ inputs.release_name }}"
        """,
        input_type="boolean",
    )
    assert not _rule()["pattern"].search(source)


def test_packaged_rule_binds_the_interpolated_input_to_its_string_declaration() -> None:
    """A separate string input must not taint an interpolated boolean input."""
    source = textwrap.dedent(
        """
        name: Typed inputs
        on:
          workflow_call:
            inputs:
              release_name:
                type: string
              dry_run:
                type: boolean
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ inputs.dry_run }}"
        """
    ).lstrip()
    assert not _rule()["pattern"].search(source)


def test_scan_file_emits_normalized_critical_finding(tmp_path: Path) -> None:
    """Verify exact vulnerable replay through the production scanner."""
    source = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")
    findings = _scan(source, tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    expected_line = next(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if line.strip() == "workflow_call:"
    )
    assert finding["line"] == expected_line
    assert finding["file"] == ".github/workflows/deploy-pages.yml"
    assert finding["severity"] == "CRITICAL"
    assert finding["source"] == "appguardrail-rule"
    assert finding["confidence"] == "high"
    assert finding["category"] == "injection"
    assert finding["cwe"] == (
        "CWE-78 - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "CWE-94 - Improper Control of Generation of Code ('Code Injection')",
        "CWE-74 - Injection",
    )
    assert finding["owasp"] == ("OWASP A03:2021 - Injection",)


def test_scan_file_keeps_reviewed_fix_clean(tmp_path: Path) -> None:
    """Verify the exact reviewed fixed workflow remains finding-free."""
    source = _FIXED_FIXTURE.read_text(encoding="utf-8")
    assert _scan(source, tmp_path) == []


def test_scan_file_respects_workflow_path_scope(tmp_path: Path) -> None:
    """Ignore identical YAML outside GitHub Actions workflow directories."""
    source = _workflow(
        """
          run: echo "${{ inputs.release_name }}"
        """
    )
    documentation = tmp_path / "docs" / "workflow.yml"
    documentation.parent.mkdir()
    documentation.write_text(source, encoding="utf-8")

    assert _RULE_ID not in {
        finding["rule_id"] for finding in _scan_file(documentation, tmp_path)
    }
