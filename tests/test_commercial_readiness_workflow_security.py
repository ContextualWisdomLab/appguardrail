"""Security-boundary tests for the hourly commercial-readiness workflow."""

from pathlib import Path


WORKFLOW_PATH = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "commercial-readiness-loop.yml"
)


def test_manual_dispatch_cannot_run_feature_branch_write_code() -> None:
    """Manual runs must fail closed unless the selected ref is the default branch."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "github.ref_name == github.event.repository.default_branch" in workflow
    assert "github.event_name == 'schedule'" in workflow
