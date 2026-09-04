"""GitHub Actions concurrency contracts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PR_WORKFLOWS = (
    "commercial-readiness-agent-coverage.yml",
    "controlplane-schema-coverage.yml",
    "openssf-evidence-coverage.yml",
    "pinned-https-coverage.yml",
    "retention-audit-coverage.yml",
    "scan-path-context-coverage.yml",
    "security-process.yml",
    "tests.yml",
)
RELEASE_WORKFLOWS = ("prepare-pypi-release.yml", "publish-pypi.yml")


def test_pr_workflows_cancel_only_superseded_heads() -> None:
    for name in PR_WORKFLOWS:
        workflow = (WORKFLOWS / name).read_text(encoding="utf-8")
        assert "${{ github.workflow }}-${{ github.repository }}-" in workflow
        assert "github.event.pull_request.number || github.run_id" in workflow
        assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in workflow


def test_release_workflows_serialize_without_dropping_delivery() -> None:
    for name in RELEASE_WORKFLOWS:
        workflow = (WORKFLOWS / name).read_text(encoding="utf-8")
        assert "group: ${{ github.workflow }}-${{ github.repository }}" in workflow
        assert "github.run_id" not in workflow.split("jobs:", 1)[0]
        assert "queue: max" in workflow
        assert "cancel-in-progress: false" in workflow
