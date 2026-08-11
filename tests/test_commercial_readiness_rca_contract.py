"""Contracts for RCA-first, feasibility-checked hourly product development."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "commercial-readiness-loop.yml"
REMEDIATION_CONTRACT = ROOT / "scripts" / "ci" / "commercial_remediation_contract.md"
OPERATOR_GUIDE = ROOT / "docs" / "commercial-readiness-loop.md"


def test_hourly_scheduler_appends_reviewed_rca_contract_before_hashing() -> None:
    """The immutable model contract must include the reviewed remediation policy."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    append_command = (
        "cat scripts/ci/commercial_remediation_contract.md "
        ">> .commercial-agent-contract.md"
    )

    assert 'cron: "17 * * * *"' in workflow
    assert append_command in workflow
    assert workflow.index("--render-agent-contract") < workflow.index(append_command)
    assert workflow.index(append_command) < workflow.index(
        "test -s .commercial-agent-contract.md"
    )
    assert workflow.index(append_command) < workflow.index(
        "chmod 0444 .commercial-agent-contract.md"
    )
    assert workflow.index(append_command) < workflow.index(
        "sha256sum .commercial-agent-contract.md"
    )
    assert "Follow the RCA and feasibility sections" in workflow
    assert "COPILOT_GITHUB_TOKEN" not in workflow


def test_rca_contract_requires_evidence_feasibility_and_no_blind_retry() -> None:
    """Remediation must be evidence-led, executable, bounded, and reversible."""
    contract = REMEDIATION_CONTRACT.read_text(encoding="utf-8")
    lowered = contract.lower()

    required_phrases = (
        "root-cause analysis",
        "exact current head",
        "reproduce",
        "candidate actions",
        "required permission",
        "required secret",
        "required tool",
        "time budget",
        "branch protection",
        "writer lease",
        "rollback",
        "smallest viable action",
        "do not blindly rerun",
        "three unsuccessful",
        "question the architecture",
        "independent non-conflicting work",
        "do not invent",
        "pull request description",
        "rca and feasibility evidence",
    )
    assert all(phrase in lowered for phrase in required_phrases)


def test_operator_guide_states_realistic_limits_and_recovery_behavior() -> None:
    """Documentation must distinguish an instruction contract from hard guarantees."""
    guide = OPERATOR_GUIDE.read_text(encoding="utf-8")
    lowered = guide.lower()

    assert "## RCA and feasibility gate" in guide
    assert "instruction-level control" in lowered
    assert "cannot prove external feasibility by prompt alone" in lowered
    assert "current repository and workflow evidence" in lowered
    assert "no feasible action" in lowered
    assert "bounded backoff" in lowered
    assert "branch protection" in lowered
    assert "independent review" in lowered
