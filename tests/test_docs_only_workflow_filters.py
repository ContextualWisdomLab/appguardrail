"""Contracts for docs-only workflow path filtering."""

from pathlib import Path

import pytest


WORKFLOWS = (
    ".github/workflows/tests.yml",
    ".github/workflows/openssf-evidence-coverage.yml",
    ".github/workflows/pinned-https-coverage.yml",
    ".github/workflows/retention-audit-coverage.yml",
    ".github/workflows/scan-path-context-coverage.yml",
)


@pytest.mark.parametrize("workflow_path", WORKFLOWS)
def test_docs_only_filters_ignore_markdown_at_any_depth(workflow_path: str) -> None:
    """Optimized workflows skip Markdown anywhere, not only at repository root."""
    workflow = Path(workflow_path).read_text(encoding="utf-8")

    assert workflow.count('      - "**.md"') == 2
    assert '      - "*.md"' not in workflow
