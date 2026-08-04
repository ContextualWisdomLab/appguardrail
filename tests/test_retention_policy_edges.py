"""Defensive edge contracts for the retention and purge policy core."""

from __future__ import annotations

from dataclasses import replace

import pytest

from appguardrail_core.retention_policy import (
    RETENTION_CATEGORIES,
    PurgePreview,
    RetentionPolicy,
    build_purge_preview,
    create_purge_receipt,
    update_retention_policy,
    verify_purge_preview,
)


TENANT_ID = 41
TIMESTAMP = "2026-08-04T12:30:00Z"


def _policy() -> RetentionPolicy:
    """Return one valid policy used by defensive boundary tests."""
    return RetentionPolicy.default(
        tenant_id=TENANT_ID,
        updated_at=TIMESTAMP,
        updated_by="owner-key-7",
    )


def _zero_counts() -> dict[str, int]:
    """Return the exact retention-category count shape with no eligible records."""
    return {category: 0 for category in RETENTION_CATEGORIES}


def _preview() -> PurgePreview:
    """Return one valid, empty purge preview."""
    return build_purge_preview(
        _policy(),
        preview_id="purge-preview-1",
        legal_hold_revision=0,
        created_at=TIMESTAMP,
        eligible_counts=_zero_counts(),
        held_counts=_zero_counts(),
    )


def test_policy_update_rejects_non_policy_and_non_mapping_changes() -> None:
    """The pure mutation boundary does not infer policy or change-object shapes."""
    with pytest.raises(ValueError, match="RetentionPolicy"):
        update_retention_policy(
            object(),
            expected_revision=1,
            changes={},
            updated_at=TIMESTAMP,
            updated_by="owner-key-7",
        )
    with pytest.raises(ValueError, match="changes must be an object"):
        update_retention_policy(
            _policy(),
            expected_revision=1,
            changes=[],
            updated_at=TIMESTAMP,
            updated_by="owner-key-7",
        )


def test_empty_policy_change_still_creates_an_auditable_revision() -> None:
    """An explicitly approved no-op is revisioned instead of silently disappearing."""
    updated = update_retention_policy(
        _policy(),
        expected_revision=1,
        changes={},
        updated_at="2026-08-04T12:31:00Z",
        updated_by="owner-key-8",
    )

    assert updated.revision == 2
    assert updated.updated_by == "owner-key-8"


def test_preview_rejects_non_policy_non_mapping_and_negative_hold_revision() -> None:
    """Preview creation requires typed policy state and exact count objects."""
    with pytest.raises(ValueError, match="RetentionPolicy"):
        build_purge_preview(
            object(),
            preview_id="purge-preview-1",
            legal_hold_revision=0,
            created_at=TIMESTAMP,
            eligible_counts=_zero_counts(),
            held_counts=_zero_counts(),
        )
    with pytest.raises(ValueError, match="count mapping"):
        build_purge_preview(
            _policy(),
            preview_id="purge-preview-1",
            legal_hold_revision=0,
            created_at=TIMESTAMP,
            eligible_counts=[],
            held_counts=_zero_counts(),
        )
    with pytest.raises(ValueError, match="legal_hold_revision"):
        build_purge_preview(
            _policy(),
            preview_id="purge-preview-1",
            legal_hold_revision=-1,
            created_at=TIMESTAMP,
            eligible_counts=_zero_counts(),
            held_counts=_zero_counts(),
        )


def test_preview_verification_rejects_non_preview_and_cutoff_shape_mutation() -> None:
    """Execution validation rejects untyped evidence and malformed cutoff snapshots."""
    with pytest.raises(ValueError, match="PurgePreview"):
        verify_purge_preview(object(), policy_revision=1, legal_hold_revision=0)

    preview = _preview()
    incomplete = replace(preview, cutoffs={"scan_history": TIMESTAMP})
    with pytest.raises(ValueError, match="cutoff mapping"):
        verify_purge_preview(incomplete, policy_revision=1, legal_hold_revision=0)

    non_mapping = replace(preview, cutoffs=[])
    with pytest.raises(ValueError, match="cutoff mapping"):
        verify_purge_preview(non_mapping, policy_revision=1, legal_hold_revision=0)


def test_receipt_creation_rejects_non_preview() -> None:
    """A completion receipt cannot be fabricated without a validated preview object."""
    with pytest.raises(ValueError, match="PurgePreview"):
        create_purge_receipt(
            object(),
            policy_revision=1,
            legal_hold_revision=0,
            receipt_id="purge-receipt-1",
            executed_at=TIMESTAMP,
            audit_event_id="audit-event-1",
        )


def test_receipt_deleted_counts_exclude_records_under_legal_hold() -> None:
    """The receipt distinguishes age-eligible records from rows actually deleted."""
    eligible = _zero_counts()
    held = _zero_counts()
    eligible["scan_history"] = 7
    held["scan_history"] = 2
    preview = build_purge_preview(
        _policy(),
        preview_id="purge-preview-1",
        legal_hold_revision=4,
        created_at=TIMESTAMP,
        eligible_counts=eligible,
        held_counts=held,
    )

    receipt = create_purge_receipt(
        preview,
        policy_revision=1,
        legal_hold_revision=4,
        receipt_id="purge-receipt-1",
        executed_at="2026-08-04T12:31:00Z",
        audit_event_id="audit-event-1",
    )

    assert receipt.deleted_counts["scan_history"] == 5
    assert receipt.held_counts["scan_history"] == 2
