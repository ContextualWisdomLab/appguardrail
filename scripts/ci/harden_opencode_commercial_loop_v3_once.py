"""Apply least-privilege refinements to the generated OpenCode scheduler."""

from __future__ import annotations

from pathlib import Path

from scripts.ci import harden_opencode_commercial_loop_v2_once as previous


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    """Replace one exact generated fragment or fail before committing output."""
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    """Generate v2, then narrow token scope and remove obsolete provider aliases."""
    previous.main()

    workflow_path = Path(".github/workflows/commercial-readiness-loop.yml")
    workflow = workflow_path.read_text(encoding="utf-8")
    workflow = _replace_once(
        workflow,
        """permissions:
  contents: write
  issues: write
  pull-requests: write
""",
        """permissions:
  contents: read
""",
        "top-level permissions",
    )
    workflow = _replace_once(
        workflow,
        """jobs:
  dispatch-reviewed-gap:
""",
        """jobs:
  dispatch-reviewed-gap:
    permissions:
      contents: write
      issues: write
      pull-requests: write
""",
        "job permissions",
    )
    workflow_path.write_text(workflow, encoding="utf-8")

    test_path = Path("tests/test_opencode_commercial_agent_contract.py")
    tests = test_path.read_text(encoding="utf-8")
    tests = _replace_once(
        tests,
        '''    assert "cancel-in-progress: false" in workflow
    assert 'cron: "17 * * * *"' in workflow
''',
        '''    assert "cancel-in-progress: false" in workflow
    assert 'cron: "17 * * * *"' in workflow
    assert "permissions:\\n  contents: read" in workflow
    assert (
        "dispatch-reviewed-gap:\\n    permissions:\\n"
        "      contents: write\\n      issues: write\\n"
        "      pull-requests: write"
    ) in workflow
''',
        "least-privilege assertions",
    )
    test_path.write_text(tests, encoding="utf-8")

    selected_roots = (
        Path("docs/superpowers/plans/2026-08-04-opencode-commercial-readiness-agent.md"),
        Path("docs/commercial-readiness-opencode.md"),
        Path("docs/adr/ADR-007-hourly-opencode-commercial-builder.md"),
        Path("tests/test_opencode_commercial_agent_contract.py"),
        Path(".github/workflows/commercial-readiness-loop.yml"),
        Path("opencode.jsonc"),
    )
    for path in selected_roots:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("nvidia-nim", "nvidia"), encoding="utf-8")

    docs_path = Path("docs/commercial-readiness-opencode.md")
    docs = docs_path.read_text(encoding="utf-8")
    docs = _replace_once(
        docs,
        "- The OpenCode action is pinned to an immutable commit.\n",
        "- The OpenCode action is pinned to an immutable commit.\n"
        "- Repository permissions are read-only by default and elevated only on the single builder job.\n",
        "least-privilege documentation",
    )
    docs_path.write_text(docs, encoding="utf-8")


if __name__ == "__main__":
    main()
