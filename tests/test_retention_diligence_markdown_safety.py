"""Regression tests for hostile identifiers in retention diligence Markdown."""

from __future__ import annotations

from dataclasses import replace

from appguardrail_core.audit_events import GENESIS_EVENT_HASH
from appguardrail_core.retention_diligence import build_retention_audit_posture
from appguardrail_core.retention_diligence_report import render_retention_audit_posture
from appguardrail_core.retention_policy import RetentionPolicy

STAMP = "2026-08-16T00:00:00Z"


def test_purge_receipt_identifier_cannot_inject_html_link_or_code_markup() -> None:
    """Render an accepted hostile receipt identifier only as literal report text."""
    policy = RetentionPolicy.default(
        tenant_id=41,
        updated_at="2026-08-15T23:00:00Z",
        updated_by="owner-17",
    )
    posture = build_retention_audit_posture(
        policy,
        legal_hold_count=0,
        audit_event_count=0,
        audit_chain_status="verified",
        audit_head_hash=GENESIS_EVENT_HASH,
        verified_at=STAMP,
    )
    hostile_identifier = (
        "<img src=x onerror=alert(1)> "
        "[click](https://attacker.example) `receipt`"
    )
    posture = replace(
        posture,
        last_purge_receipt_id=hostile_identifier,
        last_purge_executed_at=STAMP,
        last_purge_policy_revision=1,
        last_purge_legal_hold_revision=0,
    )

    report = render_retention_audit_posture(posture)

    assert "<img src=x onerror=alert(1)>" not in report
    assert "[click](https://attacker.example)" not in report
    assert "`receipt`" not in report
    assert "&lt;img src=x onerror=alert(1)&gt;" in report
    assert r"\[click\]\(https://attacker.example\)" in report
    assert r"\`receipt\`" in report
