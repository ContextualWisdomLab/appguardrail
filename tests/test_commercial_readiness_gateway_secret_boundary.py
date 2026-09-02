"""Security contracts for the commercial builder gateway credential boundary."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "commercial-readiness-loop.yml"
PROVIDER_SECRETS = (
    "BYTEZ_API_KEY",
    "NVIDIA_NIM_API_KEY",
    "NVIDIA_NIM_API_KEY_SUB",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
)


def _step_body(workflow: str, step_name: str, next_step_name: str | None = None) -> str:
    """Return one named workflow step without borrowing evidence from siblings."""
    start_marker = f"      - name: {step_name}\n"
    start = workflow.index(start_marker)
    if next_step_name is None:
        return workflow[start:]
    end_marker = f"      - name: {next_step_name}\n"
    end = workflow.index(end_marker, start + len(start_marker))
    return workflow[start:end]


def test_provider_credentials_exist_only_at_the_trusted_sidecar_bootstrap() -> None:
    """Model and post-model steps must never reacquire raw provider credentials."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    sidecar = _step_body(
        workflow,
        "Provision contextual-orchestrator orchestrator/free gateway",
        "Run the orchestrator/free OpenCode commercial builder",
    )
    post_model = _step_body(workflow, "Reject model credential disclosure")

    for secret_name in PROVIDER_SECRETS:
        expression = "${{ secrets." + secret_name + " }}"
        assert workflow.count(expression) == 1
        assert expression in sidecar
        assert expression not in post_model


def test_post_model_disclosure_check_never_sources_control_plane_shell() -> None:
    """Untrusted model execution cannot turn a mutable loader into later code execution."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    post_model = _step_body(workflow, "Reject model credential disclosure")

    assert "load_contextual_orchestrator_token.sh" not in post_model
    assert "source " not in post_model
    assert "CONTEXTUAL_ORCHESTRATOR_TOKEN_FILE" in post_model
    assert "CONTEXTUAL_ORCHESTRATOR_TOKEN" in post_model
