"""Real-world contracts for tenant retention policy and deterministic purge evidence."""

from __future__ import annotations

from dataclasses import replace

import pytest

from appguardrail_core.retention_policy import (
    DEFAULT_RETENTION_DAYS,
    RETENTION_CATEGORIES,
    PurgePreview,
    RetentionPolicy,
    RetentionPolicyConflict,
    StalePurgePreview,
    build_purge_preview,
    create_purge_receipt,
    update_retention_policy,
    verify_purge_preview,
)

TENANT_ID = 41
UPDATED_AT = "2026-08-04T12:15:00Z"
AS_OF = "2026-08-04T12:30:00Z"


def _policy(**overrides: object) -> RetentionPolicy:
    """Create a deterministic policy with optional field overrides."""
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "revision": 1,
        "scan_history_days": 90,
        "audit_event_days": 365,
        "access_key_metadata_days": 365,
        "webhook_metadata_days": 365,
        "suppression_evidence_days": 365,
        "updated_at": UPDATED_AT,
        "updated_by": "owner-key-7",
    }
    values.update(overrides)
    return RetentionPolicy(**values)


def test_default_policy_is_explicit_bounded_and_not_a_compliance_claim() -> None:
    """Every tenant receives reviewable product defaults rather than hidden permanence."""
    policy = RetentionPolicy.default(
        tenant_id=TENANT_ID,
        updated_at=UPDATED_AT,
        updated_by="owner-key-7",
    )

    assert policy.to_dict()["retention_days"] == DEFAULT_RETENTION_DAYS
    assert tuple(policy.to_dict()["retention_days"]) == RETENTION_CATEGORIES
    assert all(1 <= days <= 3650 for days in DEFAULT_RETENTION_DAYS.values())
    assert policy.revision == 1


def test_cutoffs_are_deterministic_at_real_calendar_boundaries() -> None:
    """Leap-day and exact-boundary calculations use injected UTC time, not local clocks."""
    policy = _policy(
        scan_history_days=1,
        audit_event_days=2,
        access_key_metadata_days=30,
        webhook_metadata_days=30,
        suppression_evidence_days=30,
    )

    cutoffs = policy.cutoffs(as_of="2024-03-01T00:00:00Z")

    assert cutoffs["scan_history"] == "2024-02-29T00:00:00Z"
    assert cutoffs["audit_events"] == "2024-02-28T00:00:00Z"
    assert cutoffs["access_key_metadata"] == "2024-01-31T00:00:00Z"


def test_owner_update_requires_expected_revision_and_increments_once() -> None:
    """Concurrent policy writers cannot silently overwrite a newer tenant decision."""
    original = _policy()

    updated = update_retention_policy(
        original,
        expected_revision=1,
        changes={"scan_history_days": 120, "audit_event_days": 730},
        updated_at="2026-08-04T12:20:00Z",
        updated_by="owner-key-9",
    )

    assert updated.revision == 2
    assert updated.scan_history_days == 120
    assert updated.audit_event_days == 730
    assert original.scan_history_days == 90
    with pytest.raises(RetentionPolicyConflict, match="revision"):
        update_retention_policy(
            updated,
            expected_revision=1,
            changes={"scan_history_days": 30},
            updated_at="2026-08-04T12:21:00Z",
            updated_by="owner-key-10",
        )


def test_owner_update_rejects_boolean_revision_alias() -> None:
    """Python Boolean equality cannot bypass the optimistic revision boundary."""
    with pytest.raises(ValueError, match="expected_revision"):
        update_retention_policy(
            _policy(),
            expected_revision=True,
            changes={"scan_history_days": 120},
            updated_at="2026-08-04T12:20:00Z",
            updated_by="owner-key-9",
        )


def test_update_rejects_unknown_fields_and_identity_mutation() -> None:
    """The pure update boundary cannot mutate tenant identity or accept typo fields."""
    policy = _policy()

    for changes in (
        {"tenant_id": 99},
        {"revision": 9},
        {"unknown_days": 30},
        {"updated_by": "attacker"},
    ):
        with pytest.raises(ValueError, match="unsupported policy field"):
            update_retention_policy(
                policy,
                expected_revision=1,
                changes=changes,
                updated_at="2026-08-04T12:20:00Z",
                updated_by="owner-key-9",
            )


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"tenant_id": 0}, "tenant_id"),
        ({"revision": 0}, "revision"),
        ({"scan_history_days": 0}, "scan_history_days"),
        ({"audit_event_days": 3651}, "audit_event_days"),
        ({"access_key_metadata_days": True}, "access_key_metadata_days"),
        ({"updated_at": "2026-08-04"}, "updated_at"),
        ({"updated_by": ""}, "updated_by"),
    ],
)
def test_policy_rejects_unbounded_or_noncanonical_values(
    overrides: dict[str, object],
    match: str,
) -> None:
    """Unsafe policy values fail before they can become persisted tenant controls."""
    with pytest.raises(ValueError, match=match):
        _policy(**overrides)


def test_purge_preview_binds_policy_holds_cutoffs_and_counts() -> None:
    """A purge preview is a stable receipt candidate for one exact tenant snapshot."""
    policy = _policy()
    preview = build_purge_preview(
        policy,
        preview_id="purge-preview-1",
        legal_hold_revision=3,
        created_at=AS_OF,
        eligible_counts={
            "scan_history": 12,
            "audit_events": 0,
            "access_key_metadata": 1,
            "webhook_metadata": 1,
            "suppression_evidence": 2,
        },
        held_counts={
            "scan_history": 2,
            "audit_events": 0,
            "access_key_metadata": 0,
            "webhook_metadata": 1,
            "suppression_evidence": 1,
        },
    )

    assert isinstance(preview, PurgePreview)
    assert preview.policy_revision == 1
    assert preview.legal_hold_revision == 3
    assert preview.eligible_counts["scan_history"] == 12
    assert preview.held_counts["scan_history"] == 2
    assert preview.cutoffs == policy.cutoffs(as_of=AS_OF)
    assert len(preview.preview_hash) == 64
    assert preview.to_dict()["preview_hash"] == preview.preview_hash
    verify_purge_preview(preview, policy_revision=1, legal_hold_revision=3)


def test_preview_hash_is_independent_of_input_mapping_order() -> None:
    """Equivalent count mappings create the same idempotency and stale-check identity."""
    policy = _policy()
    first = build_purge_preview(
        policy,
        preview_id="purge-preview-1",
        legal_hold_revision=3,
        created_at=AS_OF,
        eligible_counts={
            category: index for index, category in enumerate(RETENTION_CATEGORIES)
        },
        held_counts={category: 0 for category in RETENTION_CATEGORIES},
    )
    second = build_purge_preview(
        policy,
        preview_id="purge-preview-1",
        legal_hold_revision=3,
        created_at=AS_OF,
        eligible_counts=dict(reversed(tuple(first.eligible_counts.items()))),
        held_counts=dict(reversed(tuple(first.held_counts.items()))),
    )

    assert first.preview_hash == second.preview_hash


@pytest.mark.parametrize(
    ("policy_revision", "legal_hold_revision"),
    [(2, 3), (1, 4)],
)
def test_preview_fails_closed_after_policy_or_legal_hold_change(
    policy_revision: int,
    legal_hold_revision: int,
) -> None:
    """No deletion may use counts calculated before a policy or hold revision changed."""
    preview = build_purge_preview(
        _policy(),
        preview_id="purge-preview-1",
        legal_hold_revision=3,
        created_at=AS_OF,
        eligible_counts={category: 0 for category in RETENTION_CATEGORIES},
        held_counts={category: 0 for category in RETENTION_CATEGORIES},
    )

    with pytest.raises(StalePurgePreview, match="stale"):
        verify_purge_preview(
            preview,
            policy_revision=policy_revision,
            legal_hold_revision=legal_hold_revision,
        )


@pytest.mark.parametrize(
    ("policy_revision", "legal_hold_revision", "match"),
    [(True, 3, "policy_revision"), (1, True, "legal_hold_revision")],
)
def test_preview_verification_rejects_boolean_revision_aliases(
    policy_revision: object,
    legal_hold_revision: object,
    match: str,
) -> None:
    """Current-state checks reject Boolean values that compare equal to integers."""
    preview = build_purge_preview(
        _policy(),
        preview_id="purge-preview-1",
        legal_hold_revision=3,
        created_at=AS_OF,
        eligible_counts={category: 0 for category in RETENTION_CATEGORIES},
        held_counts={category: 0 for category in RETENTION_CATEGORIES},
    )

    with pytest.raises(ValueError, match=match):
        verify_purge_preview(
            preview,
            policy_revision=policy_revision,
            legal_hold_revision=legal_hold_revision,
        )


def test_receipt_preserves_preview_counts_without_customer_evidence() -> None:
    """Completed purge evidence contains counts and identity, never deleted record bodies."""
    preview = build_purge_preview(
        _policy(),
        preview_id="purge-preview-1",
        legal_hold_revision=3,
        created_at=AS_OF,
        eligible_counts={category: 1 for category in RETENTION_CATEGORIES},
        held_counts={category: 0 for category in RETENTION_CATEGORIES},
    )

    receipt = create_purge_receipt(
        preview,
        policy_revision=1,
        legal_hold_revision=3,
        receipt_id="purge-receipt-1",
        executed_at="2026-08-04T12:35:00Z",
        audit_event_id="audit-event-9",
    )

    rendered = str(receipt.to_dict())
    assert receipt.preview_hash == preview.preview_hash
    assert receipt.deleted_counts == preview.eligible_counts
    assert receipt.audit_event_id == "audit-event-9"
    assert "findings" not in rendered
    assert "snippet" not in rendered


def test_receipt_creation_rejects_stale_preview_state() -> None:
    """Receipt creation cannot bypass the final current-state revision check."""
    preview = build_purge_preview(
        _policy(),
        preview_id="purge-preview-1",
        legal_hold_revision=3,
        created_at=AS_OF,
        eligible_counts={category: 0 for category in RETENTION_CATEGORIES},
        held_counts={category: 0 for category in RETENTION_CATEGORIES},
    )

    with pytest.raises(StalePurgePreview, match="stale"):
        create_purge_receipt(
            preview,
            policy_revision=2,
            legal_hold_revision=3,
            receipt_id="purge-receipt-1",
            executed_at="2026-08-04T12:35:00Z",
            audit_event_id="audit-event-9",
        )


def test_preview_rejects_missing_extra_negative_and_held_overflow_counts() -> None:
    """Preview evidence cannot omit a data class or claim more held rows than eligible."""
    policy = _policy()
    valid = {category: 0 for category in RETENTION_CATEGORIES}

    bad_pairs = [
        ({"scan_history": 1}, valid),
        ({**valid, "unknown_records": 1}, valid),
        ({**valid, "scan_history": -1}, valid),
        ({**valid, "scan_history": 1}, {**valid, "scan_history": 2}),
        ({**valid, "scan_history": True}, valid),
    ]
    for eligible_counts, held_counts in bad_pairs:
        with pytest.raises(ValueError, match="count"):
            build_purge_preview(
                policy,
                preview_id="purge-preview-1",
                legal_hold_revision=0,
                created_at=AS_OF,
                eligible_counts=eligible_counts,
                held_counts=held_counts,
            )


def test_preview_and_receipt_validate_identity_and_canonical_time() -> None:
    """Purge identities and UTC times are bounded before becoming audit evidence."""
    valid_counts = {category: 0 for category in RETENTION_CATEGORIES}

    with pytest.raises(ValueError, match="preview_id"):
        build_purge_preview(
            _policy(),
            preview_id="",
            legal_hold_revision=0,
            created_at=AS_OF,
            eligible_counts=valid_counts,
            held_counts=valid_counts,
        )
    preview = build_purge_preview(
        _policy(),
        preview_id="purge-preview-1",
        legal_hold_revision=0,
        created_at=AS_OF,
        eligible_counts=valid_counts,
        held_counts=valid_counts,
    )
    with pytest.raises(ValueError, match="executed_at"):
        create_purge_receipt(
            preview,
            policy_revision=1,
            legal_hold_revision=0,
            receipt_id="purge-receipt-1",
            executed_at="yesterday",
            audit_event_id="audit-event-1",
        )
    with pytest.raises(ValueError, match="cannot precede"):
        create_purge_receipt(
            preview,
            policy_revision=1,
            legal_hold_revision=0,
            receipt_id="purge-receipt-1",
            executed_at="2026-08-04T12:29:59Z",
            audit_event_id="audit-event-1",
        )
    with pytest.raises(ValueError, match="receipt_id"):
        create_purge_receipt(
            preview,
            policy_revision=1,
            legal_hold_revision=0,
            receipt_id="",
            executed_at=AS_OF,
            audit_event_id="audit-event-1",
        )
    with pytest.raises(ValueError, match="audit_event_id"):
        create_purge_receipt(
            preview,
            policy_revision=1,
            legal_hold_revision=0,
            receipt_id="purge-receipt-1",
            executed_at=AS_OF,
            audit_event_id="",
        )


def test_manual_preview_mutation_is_detected_before_execution() -> None:
    """Callers cannot alter a frozen preview through dataclass replacement and retain trust."""
    preview = build_purge_preview(
        _policy(),
        preview_id="purge-preview-1",
        legal_hold_revision=0,
        created_at=AS_OF,
        eligible_counts={category: 0 for category in RETENTION_CATEGORIES},
        held_counts={category: 0 for category in RETENTION_CATEGORIES},
    )
    tampered = replace(
        preview, eligible_counts={**preview.eligible_counts, "scan_history": 9}
    )

    with pytest.raises(ValueError, match="preview hash"):
        verify_purge_preview(tampered, policy_revision=1, legal_hold_revision=0)
