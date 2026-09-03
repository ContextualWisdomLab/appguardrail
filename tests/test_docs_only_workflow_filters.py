"""Contracts preventing documentation-backed behavior from bypassing CI."""

from pathlib import Path

import pytest


WORKFLOWS = (
    ".github/workflows/tests.yml",
    ".github/workflows/openssf-evidence-coverage.yml",
    ".github/workflows/pinned-https-coverage.yml",
    ".github/workflows/retention-audit-coverage.yml",
    ".github/workflows/scan-path-context-coverage.yml",
)


def _event_block(workflow: str, event: str) -> str:
    """Return one peer event block from the workflow's top-level ``on`` mapping."""
    lines = workflow.splitlines()
    marker = f"  {event}:"
    try:
        start = lines.index(marker)
    except ValueError as exc:
        raise AssertionError(f"missing workflow event: {event}") from exc

    block: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("  ") and not line.startswith("    "):
            break
        block.append(line)
    return "\n".join(block)


@pytest.mark.parametrize("workflow_path", WORKFLOWS)
def test_contract_sensitive_workflows_do_not_skip_documentation(
    workflow_path: str,
) -> None:
    """Docs and policy Markdown remain covered until a dedicated contract lane exists."""
    workflow = Path(workflow_path).read_text(encoding="utf-8")

    for event in ("push", "pull_request"):
        assert "paths-ignore:" not in _event_block(workflow, event)
