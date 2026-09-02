"""Handoff contract tests for recurring commercial-readiness work."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ci" / "commercial_readiness_loop.py"
DOCUMENTATION_PATH = ROOT / "docs" / "opencode-commercial-readiness-agent.md"
LOOP_DOCUMENTATION_PATH = ROOT / "docs" / "commercial-readiness-loop.md"
CHANGELOG_PATH = ROOT / "CHANGELOG.d" / "872-opencode-commercial-agent.md"
PLAN_PATH = (
    ROOT
    / "docs"
    / "superpowers"
    / "plans"
    / "2026-08-06-opencode-commercial-readiness-agent.md"
)


def _load_module():
    """Load the scheduled-loop module from the repository tree."""
    spec = importlib.util.spec_from_file_location(
        "commercial_readiness_loop_handoff",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generated_gap_requires_issue_closure_and_next_backlog_decision() -> None:
    """Each completed slice closes its issue and keeps the loop self-renewing."""
    module = _load_module()

    body = module.render_gap_issue(module.COMMERCIAL_GAPS[0])

    assert "Closes" in body
    assert "COMMERCIAL_GAPS" in body
    assert "remove the completed gap" in body
    assert "next evidence-backed" in body


def test_generated_gap_routes_research_design_and_analytics_tools() -> None:
    """Future slices use authoritative evidence and specialist tools when relevant."""
    module = _load_module()

    body = module.render_gap_issue(module.COMMERCIAL_GAPS[0])

    assert "authoritative primary" in body
    assert "peer-reviewed" in body
    assert "APA 7th" in body
    assert "Context7" in body
    assert "Consensus" in body
    assert "Figma or Product Design" in body
    assert "Visualize" in body


def test_operator_documentation_records_agent_trust_and_recovery() -> None:
    """Operators can understand the scheduled agent without reading workflow code."""
    documentation = DOCUMENTATION_PATH.read_text(encoding="utf-8")

    required = (
        "contextual-orchestrator",
        "orchestrator/free",
        "CONTEXTUAL_ORCHESTRATOR_TOKEN",
        "NVIDIA_NIM_API_KEY",
        "commercial-builder",
        "73b250f568d8892ead48bff85de06a4e3eb34e93",
        "17 * * * *",
        "default branch",
        "PR-first",
        "fail closed",
        "COMMERCIAL_GAPS",
        "untrusted",
        ".commercial-agent-contract.md",
        "review-agent credentials",
        "APA 7th",
        "OpenCode documentation",
        "GitHub Docs",
        "naruon",
    )
    assert all(item in documentation for item in required)
    assert "COPILOT_GITHUB_TOKEN" in documentation
    assert "must never be configured" in documentation
    assert "does not read the issue" in documentation
    assert "marker-verification target" not in documentation


def test_legacy_loop_documentation_matches_opencode_only_handoff() -> None:
    """No operator document may revive the removed mutable Jules-label path."""
    documentation = LOOP_DOCUMENTATION_PATH.read_text(encoding="utf-8")
    lowered = documentation.lower()

    assert "jules" not in lowered
    assert "opencode" in lowered
    assert "nvidia_nim_api_key" in lowered
    assert "read-only reconciliation" in lowered
    assert "issue title, body, and comments" in lowered
    assert ".commercial-agent-contract.md" in documentation
    assert "exactly one" in lowered
    assert "must not merge" in lowered


def test_changelog_fragment_records_jules_replacement_and_secret_boundary() -> None:
    """The next release notes the buyer-visible automation and credential change."""
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")

    assert "OpenCode" in changelog
    assert "NVIDIA_NIM_API_KEY" in changelog
    assert "direct-provider" in changelog.lower()
    assert "Jules" not in changelog
    assert "review-agent" in changelog
    assert "registry" in changelog.lower()
    assert "hour" in changelog.lower()


def test_implementation_plan_is_dated_and_preserves_protected_merge_boundary() -> None:
    """The ADR-style plan records deployment order, rollback, and merge gates."""
    plan = PLAN_PATH.read_text(encoding="utf-8")

    assert "2026-08-06" in plan
    assert "Threat model" in plan
    assert "RED" in plan and "GREEN" in plan
    assert "rollback" in plan.lower()
    assert "100%" in plan
    assert "exact-head" in plan
    assert "must not merge" in plan.lower()
