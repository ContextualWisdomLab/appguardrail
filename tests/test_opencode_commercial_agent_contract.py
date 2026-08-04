"""Security and orchestration contracts for the hourly OpenCode builder."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "commercial-readiness-loop.yml"
CONFIG_PATH = ROOT / "opencode.jsonc"
ACTION_PIN = "77fc88c8ade8e5a620ebbe1197f3a572d29ae91a"
MODEL = "nvidia-nim/nvidia/llama-3.3-nemotron-super-49b-v1.5"


def test_commercial_builder_uses_nvidia_nim_and_bounded_permissions() -> None:
    """The development agent is write-capable but cannot escape the repository."""
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    assert config["model"] == MODEL
    assert config["small_model"] == "nvidia-nim/meta/llama-3.3-70b-instruct"
    provider = config["provider"]["nvidia-nim"]
    assert provider["options"] == {
        "baseURL": "https://integrate.api.nvidia.com/v1",
        "apiKey": "{env:NVIDIA_API_KEY}",
    }
    agent = config["agent"]["commercial-builder"]
    assert agent["mode"] == "primary"
    assert agent["steps"] == 40
    assert agent["permission"]["edit"] == "allow"
    assert agent["permission"]["bash"] == "allow"
    assert agent["permission"]["external_directory"] == "deny"
    assert agent["permission"]["webfetch"] == "deny"
    assert agent["permission"]["websearch"] == "deny"


def test_workflow_invokes_immutable_opencode_action_only_for_active_issue() -> None:
    """Selector output gates the secret-bearing build agent on a positive issue."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert f"anomalyco/opencode/github@{ACTION_PIN}" in workflow
    assert f"model: {MODEL}" in workflow
    assert "agent: commercial-builder" in workflow
    assert 'share: "false"' in workflow
    assert 'use_github_token: "true"' in workflow
    assert "steps.decision.outputs.action == 'dispatch-gap'" in workflow
    assert "steps.decision.outputs.action == 'wait-gap'" in workflow
    assert "steps.decision.outputs.issue_number != ''" in workflow
    assert "steps.decision.outputs.issue_number != 'null'" in workflow
    assert "NVIDIA_API_KEY: ${{ secrets.NVIDIA_NIM_API_KEY }}" in workflow
    assert "GITHUB_TOKEN: ${{ github.token }}" in workflow
    assert "test -n \"${NVIDIA_API_KEY:-}\"" in workflow


def test_workflow_keeps_review_agent_credentials_out_of_development_path() -> None:
    """The scheduler must not reuse or perturb independent review credentials."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    lowered = workflow.lower()

    assert "jules" not in lowered
    assert "copilot" not in lowered
    assert "PR_REVIEW_MERGE_TOKEN" not in workflow
    assert "OPENCODE_APPROVE_TOKEN" not in workflow
    assert "STRIX_GITHUB_MODELS_TOKEN" not in workflow
    assert workflow.count("secrets.") == 1
    assert "secrets.NVIDIA_NIM_API_KEY" in workflow


def test_agent_prompt_enforces_reviewable_single_pr_handoff() -> None:
    """The build prompt preserves TDD, evidence, and protected merge boundaries."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    required_phrases = (
        "Read the exact active issue",
        "Write the failing tests first",
        "100% statement coverage",
        "complete docstrings",
        "APA 7th",
        "target `develop`",
        "Open exactly one pull request",
        "Do not merge",
        "Do not tag, publish, or release",
        "NVIDIA_NIM_API_KEY",
        "naruon",
    )
    assert all(phrase in workflow for phrase in required_phrases)


def test_selector_outputs_are_validated_before_agent_execution() -> None:
    """Malformed selector JSON cannot become an issue or credential target."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "jq -e '.action" in workflow
    assert "jq -e '.issue_number" in workflow
    assert "dispatch-gap|wait-gap|wait-prs|complete" in workflow
    assert "issue_number must be a positive integer" in workflow
    assert "action=$action" in workflow
    assert "issue_number=$issue_number" in workflow
