"""Buyer-diligence contracts for non-secret tenant retention and audit posture."""
from __future__ import annotations

from dataclasses import replace

import pytest

from appguardrail_core.audit_events import GENESIS_EVENT_HASH, create_audit_event
from appguardrail_core.reports import ReportContext, render_buyer_diligence_report
from appguardrail_core.retention_diligence import (
    RetentionAuditPosture,
    build_retention_audit_posture,
)
from appguardrail_core.retention_policy import (
    RETENTION_CATEGORIES,
    PurgeReceipt,
    RetentionPolicy,
)

STAMP = "2026-08-16T00:00:00Z"


def policy(*, tenant_id: int = 41) -> RetentionPolicy:
    """Return one deterministic tenant retention policy fixture."""
    return RetentionPolicy.default(
        tenant_id=tenant_id,
        updated_at="2026-08-15T23:00:00Z",
        updated_by="owner-17",
    )


def receipt(*, tenant_id: int = 41) -> PurgeReceipt:
    """Return one non-secret completed purge receipt fixture."""
    return PurgeReceipt(
        receipt_id="purge-20260816-001",
        tenant_id=tenant_id,
        preview_id="preview-20260816-001",
        preview_hash="a" * 64,
        policy_revision=1,
        legal_hold_revision=2,
        cutoffs={category: "2026-05-18T00:00:00Z" for category in RETENTION_CATEGORIES},
        deleted_counts={category: 3 for category in RETENTION_CATEGORIES},
        held_counts={category: 1 for category in RETENTION_CATEGORIES},
        executed_at="2026-08-16T00:00:00Z",
        audit_event_id="audit-purge-001",
    )


def test_verified_posture_is_buyer_actionable_and_non_secret() -> None:
    """Verified evidence exposes decisions and timestamps without customer payloads."""
    event = create_audit_event(
        tenant_id=41,
        sequence_number=1,
        event_id="audit-policy-001",
        event_type="retention.policy.updated",
        actor_id="owner-17",
        request_id="req-871",
        occurred_at="2026-08-15T23:00:00Z",
        summary={"authorization": "Bearer secret-token", "policy_revision": 1},
        previous_event_hash=GENESIS_EVENT_HASH,
    )
    posture = build_retention_audit_posture(
        policy(),
        legal_hold_count=2,
        audit_event_count=1,
        audit_chain_status="verified",
        audit_head_hash=event.event_hash,
        verified_at=STAMP,
        last_purge_receipt=receipt(),
    )

    payload = posture.to_dict()
    assert payload["evidence_status"] == "verified"
    assert payload["policy_revision"] == 1
    assert payload["legal_hold_count"] == 2
    assert payload["audit_chain"] == {
        "status": "verified",
        "event_count": 1,
        "head_hash": event.event_hash,
    }
    assert payload["last_purge"] == {
        "receipt_id": "purge-20260816-001",
        "executed_at": "2026-08-16T00:00:00Z",
        "policy_revision": 1,
        "legal_hold_revision": 2,
    }
    serialized = str(payload).lower()
    assert "bearer secret-token" not in serialized
    assert "authorization" not in serialized
    assert "tenant_id" not in serialized


def test_unverified_or_failed_chain_fails_closed_for_diligence() -> None:
    """Missing or failed chain verification cannot be represented as verified evidence."""
    for status in ("unverified", "failed"):
        posture = build_retention_audit_posture(
            policy(),
            legal_hold_count=0,
            audit_event_count=4,
            audit_chain_status=status,
            audit_head_hash="b" * 64,
            verified_at=STAMP,
        )
        assert posture.evidence_status == "incomplete"
        assert posture.to_dict()["audit_chain"]["status"] == status


def test_posture_rejects_cross_tenant_receipts_and_ambiguous_evidence() -> None:
    """Diligence aggregation cannot mix tenant receipts or accept malformed counters/hashes."""
    with pytest.raises(ValueError, match="tenant"):
        build_retention_audit_posture(
            policy(tenant_id=41),
            legal_hold_count=0,
            audit_event_count=1,
            audit_chain_status="verified",
            audit_head_hash="c" * 64,
            verified_at=STAMP,
            last_purge_receipt=receipt(tenant_id=42),
        )
    for kwargs in (
        {"legal_hold_count": True},
        {"audit_event_count": -1},
        {"audit_chain_status": "passing"},
        {"audit_head_hash": "short"},
        {"verified_at": "yesterday"},
    ):
        values = {
            "legal_hold_count": 0,
            "audit_event_count": 1,
            "audit_chain_status": "verified",
            "audit_head_hash": "c" * 64,
            "verified_at": STAMP,
        }
        values.update(kwargs)
        with pytest.raises(ValueError):
            build_retention_audit_posture(policy(), **values)


def test_posture_dataclass_revalidates_public_construction() -> None:
    """Direct dataclass construction cannot bypass the public evidence boundary."""
    posture = build_retention_audit_posture(
        policy(),
        legal_hold_count=0,
        audit_event_count=0,
        audit_chain_status="verified",
        audit_head_hash=GENESIS_EVENT_HASH,
        verified_at=STAMP,
    )
    with pytest.raises(ValueError):
        replace(posture, audit_head_hash="not-a-hash")


def test_buyer_report_surfaces_posture_and_next_action_without_customer_data() -> None:
    """Buyer report includes the posture while never carrying raw tenant evidence."""
    posture = build_retention_audit_posture(
        policy(),
        legal_hold_count=2,
        audit_event_count=8,
        audit_chain_status="verified",
        audit_head_hash="d" * 64,
        verified_at=STAMP,
        last_purge_receipt=receipt(),
    )
    report = render_buyer_diligence_report(
        [],
        ReportContext(
            repository="ContextualWisdomLab/appguardrail",
            commit="abc123",
            generated_at=STAMP,
            retention_audit_posture=posture,
        ),
    )
    assert "## Retention And Audit Posture" in report
    assert "Evidence status: Verified" in report
    assert "Policy revision: 1" in report
    assert "Active legal holds: 2" in report
    assert "Audit chain: Verified (8 events)" in report
    assert "Last purge: purge-20260816-001 at 2026-08-16T00:00:00Z" in report
    assert "Next action: re-verify this posture against the current tenant state before acquisition reliance." in report
    assert "tenant_id" not in report.lower()
    assert "authorization" not in report.lower()


def test_buyer_report_marks_missing_posture_as_not_supplied() -> None:
    """Default reports make missing retention evidence explicit instead of implying compliance."""
    report = render_buyer_diligence_report(
        [],
        ReportContext(generated_at=STAMP),
    )
    assert "## Retention And Audit Posture" in report
    assert "Evidence status: Not supplied" in report
    assert "Next action: supply a current tenant retention/audit posture snapshot before relying on deletion or audit claims." in report
