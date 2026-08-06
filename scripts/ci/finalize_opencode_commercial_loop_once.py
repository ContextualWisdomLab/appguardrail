"""Finalize the OpenCode scheduler from the latest branch state exactly once."""

from __future__ import annotations

from pathlib import Path


REFERENCES = '''## References

Anomaly. (n.d.-a). *Agents*. OpenCode. Retrieved August 6, 2026, from https://opencode.ai/docs/agents/

Anomaly. (n.d.-b). *GitHub integration*. OpenCode. Retrieved August 6, 2026, from https://opencode.ai/docs/github/

Anomaly. (n.d.-c). *Permissions*. OpenCode. Retrieved August 6, 2026, from https://opencode.ai/docs/permissions/

Anomaly. (n.d.-d). *Providers: NVIDIA*. OpenCode. Retrieved August 6, 2026, from https://opencode.ai/docs/providers/

GitHub. (n.d.). *Use GITHUB_TOKEN for authentication in workflows*. GitHub Docs. Retrieved August 6, 2026, from https://docs.github.com/actions/security-for-github-actions/security-guides/automatic-token-authentication

NVIDIA. (n.d.). *NVIDIA NIM API reference*. NVIDIA API Catalog. Retrieved August 6, 2026, from https://docs.api.nvidia.com/nim/
'''


def _ensure_generated_files() -> None:
    """Generate the complete split-job design when no earlier pass committed it."""
    if Path("scripts/ci/render_commercial_gap_contract.py").exists():
        return
    from scripts.ci import harden_opencode_commercial_loop_v4_once as generator

    generator.main()


def _apply_bounded_issue_permission() -> None:
    """Allow registry issue creation without granting selector code-write access."""
    workflow_path = Path(".github/workflows/commercial-readiness-loop.yml")
    workflow = workflow_path.read_text(encoding="utf-8")
    workflow = workflow.replace(
        """    permissions:
      contents: read
      issues: read
      pull-requests: read
""",
        """    permissions:
      contents: read
      issues: write
      pull-requests: read
""",
    )
    required = """    permissions:
      contents: read
      issues: write
      pull-requests: read
"""
    if workflow.count(required) != 1:
        raise SystemExit("selector permissions are not in the bounded final state")
    workflow_path.write_text(workflow, encoding="utf-8")

    tests_path = Path("tests/test_opencode_commercial_agent_contract.py")
    tests = tests_path.read_text(encoding="utf-8")
    tests = tests.replace(
        '"      contents: read\\n      issues: read\\n      pull-requests: read"',
        '"      contents: read\\n      issues: write\\n      pull-requests: read"',
    )
    tests = tests.replace(
        "def test_selector_is_read_only_and_builder_receives_write_only_when_active()",
        "def test_selector_has_only_bounded_issue_write_and_builder_is_activity_gated()",
    ).replace(
        '"""PR-first selection cannot write and inactive schedules never reach the builder."""',
        '"""Selection can create one registry issue but cannot write code or pull requests."""',
    )
    if "issues: write" not in tests:
        raise SystemExit("selector permission test was not updated")
    tests_path.write_text(tests, encoding="utf-8")


def _apply_docs() -> None:
    """Align the operator narrative and APA 7 references with final behavior."""
    docs_path = Path("docs/commercial-readiness-opencode.md")
    docs = docs_path.read_text(encoding="utf-8")
    docs = docs.replace(
        "The selector job has read-only contents, issue, and pull-request permissions.",
        "The selector job has read-only contents and pull-request permissions plus issue write permission solely to create the next checked-in registry gap.",
    )
    marker = "## References\n"
    if marker not in docs:
        raise SystemExit("operator reference section is missing")
    prefix, _marker, _old = docs.partition(marker)
    docs_path.write_text(prefix.rstrip() + "\n\n" + REFERENCES, encoding="utf-8")

    adr_path = Path("docs/adr/ADR-007-hourly-opencode-commercial-builder.md")
    adr = adr_path.read_text(encoding="utf-8")
    adr = adr.replace(
        "The read-only selector and write-capable builder are separate jobs;",
        "The repository-read-only selector and write-capable builder are separate jobs; the selector has bounded issue write permission for registry-backed issue creation, and",
    )
    adr_path.write_text(adr, encoding="utf-8")


def _validate_final_state() -> None:
    """Fail before verification if any critical final contract is missing."""
    required_files = (
        ".github/workflows/commercial-readiness-loop.yml",
        ".github/workflows/commercial-agent-coverage.yml",
        "opencode.jsonc",
        "scripts/ci/render_commercial_gap_contract.py",
        "tests/test_render_commercial_gap_contract.py",
        "tests/test_opencode_commercial_agent_contract.py",
        "docs/commercial-readiness-opencode.md",
        "docs/adr/ADR-007-hourly-opencode-commercial-builder.md",
        "CHANGELOG.d/872-opencode-commercial-loop.md",
    )
    missing = [name for name in required_files if not Path(name).is_file()]
    if missing:
        raise SystemExit("missing final OpenCode files: " + ", ".join(missing))
    workflow = Path(required_files[0]).read_text(encoding="utf-8")
    required_fragments = (
        "select-reviewed-gap:",
        "dispatch-reviewed-gap:",
        "issues: write",
        "render_commercial_gap_contract",
        "sha256sum --check",
        "nvidia/nvidia/llama-3.3-nemotron-super-49b-v1.5",
        "secrets.NVIDIA_NIM_API_KEY",
    )
    if not all(fragment in workflow for fragment in required_fragments):
        raise SystemExit("final scheduler contract is incomplete")
    if "nvidia-nim" in workflow.lower() or "copilot" in workflow.lower() or "jules" in workflow.lower():
        raise SystemExit("obsolete provider or agent credential path remains")


def main() -> None:
    """Generate if needed, normalize permissions/docs, and validate final files."""
    _ensure_generated_files()
    _apply_bounded_issue_permission()
    _apply_docs()
    _validate_final_state()


if __name__ == "__main__":
    main()
