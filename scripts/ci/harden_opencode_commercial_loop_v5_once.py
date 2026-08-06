"""Permit only the issue write required by the reviewed gap registry."""

from __future__ import annotations

from pathlib import Path


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    """Replace one exact reviewed fragment or fail before writing output."""
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    """Align selector permissions with its bounded issue-creation responsibility."""
    workflow_path = Path(".github/workflows/commercial-readiness-loop.yml")
    workflow = workflow_path.read_text(encoding="utf-8")
    workflow = _replace_once(
        workflow,
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
        "selector permissions",
    )
    workflow_path.write_text(workflow, encoding="utf-8")

    tests_path = Path("tests/test_opencode_commercial_agent_contract.py")
    tests = tests_path.read_text(encoding="utf-8")
    tests = _replace_once(
        tests,
        '"      contents: read\\n      issues: read\\n      pull-requests: read"',
        '"      contents: read\\n      issues: write\\n      pull-requests: read"',
        "selector permission assertion",
    )
    tests = tests.replace(
        "def test_selector_is_read_only_and_builder_receives_write_only_when_active()",
        "def test_selector_has_only_bounded_issue_write_and_builder_is_activity_gated()",
    ).replace(
        '"""PR-first selection cannot write and inactive schedules never reach the builder."""',
        '"""Selection can create one registry issue but cannot write code or pull requests."""',
    )
    tests_path.write_text(tests, encoding="utf-8")

    docs_path = Path("docs/commercial-readiness-opencode.md")
    docs = docs_path.read_text(encoding="utf-8")
    docs = _replace_once(
        docs,
        "The selector job has read-only contents, issue, and pull-request permissions.",
        "The selector job has read-only contents and pull-request permissions plus issue write permission solely to create the next checked-in registry gap.",
        "selector permission documentation",
    )
    docs_path.write_text(docs, encoding="utf-8")

    adr_path = Path("docs/adr/ADR-007-hourly-opencode-commercial-builder.md")
    adr = adr_path.read_text(encoding="utf-8")
    adr = adr.replace(
        "The read-only selector and write-capable builder are separate jobs;",
        "The repository-read-only selector and write-capable builder are separate jobs; the selector has bounded issue write permission for registry-backed issue creation, and",
    )
    adr_path.write_text(adr, encoding="utf-8")


if __name__ == "__main__":
    main()
