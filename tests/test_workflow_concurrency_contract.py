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


def _top_level_concurrency(workflow: str) -> str:
    lines = workflow.splitlines()
    start = lines.index("concurrency:")
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index] and not lines[index][0].isspace()
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def test_pr_workflows_cancel_only_superseded_heads() -> None:
    for name in PR_WORKFLOWS:
        workflow = (WORKFLOWS / name).read_text(encoding="utf-8")
        concurrency = _top_level_concurrency(workflow)
        assert (
            "group: ${{ github.workflow }}-${{ github.repository }}-"
            "${{ github.event_name == 'pull_request' && github.run_attempt == 1 "
            "&& github.event.pull_request.number || github.run_id }}"
        ) in concurrency
        assert (
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}"
            in concurrency
        )
        assert (
            "types: [opened, synchronize, reopened, ready_for_review]"
            in workflow
        )
        assert "converted_to_draft" not in workflow.split("permissions:", 1)[0]
        assert "closed" not in workflow.split("permissions:", 1)[0]
        assert "github.event.pull_request.draft == false" in workflow
        assert "github.event.action != 'closed'" in workflow


def test_release_workflows_serialize_without_dropping_delivery() -> None:
    for name in RELEASE_WORKFLOWS:
        workflow = (WORKFLOWS / name).read_text(encoding="utf-8")
        concurrency = _top_level_concurrency(workflow)
        assert "group: ${{ github.workflow }}-${{ github.repository }}" in concurrency
        assert "github.run_id" not in concurrency
        assert "queue: max" in concurrency
        assert "cancel-in-progress: false" in concurrency
