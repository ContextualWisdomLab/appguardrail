"""Repository-agent contract tests for commercial-readiness tasks."""

from pathlib import Path


AGENTS_PATH = Path(__file__).resolve().parents[1] / "AGENTS.md"


def test_jules_commercial_readiness_work_uses_reviewed_issue_contract() -> None:
    """Jules must preserve the bounded issue scope and protected merge path."""
    guidance = AGENTS_PATH.read_text(encoding="utf-8")

    assert "commercial-readiness" in guidance
    assert "issue body" in guidance
    assert "test first" in guidance.lower()
    assert "100%" in guidance
    assert "Closes #" in guidance
    assert "develop" in guidance
    assert "required checks" in guidance.lower()
