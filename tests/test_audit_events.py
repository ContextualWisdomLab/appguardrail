"""Real-world contracts for tenant-scoped, tamper-evident audit events."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from appguardrail_core.audit_events import (
    GENESIS_EVENT_HASH,
    AuditEvent,
    create_audit_event,
    recompute_event_hash,
    sanitize_audit_summary,
    verify_audit_chain,
)


TENANT_ID = 41
OCCURRED_AT = "2026-08-04T12:10:00Z"


def _event(
    *,
    sequence_number: int = 1,
    previous_event_hash: str = GENESIS_EVENT_HASH,
    tenant_id: int = TENANT_ID,
    summary: dict[str, object] | None = None,
) -> AuditEvent:
    """Create one deterministic audit event for chain-integrity tests."""
    return create_audit_event(
        tenant_id=tenant_id,
        sequence_number=sequence_number,
        event_id=f"audit-event-{sequence_number}",
        event_type="retention.policy.updated",
        actor_id="owner-key-7",
        request_id=f"request-{sequence_number}",
        occurred_at=OCCURRED_AT,
        summary=summary or {"policy_revision": sequence_number},
        previous_event_hash=previous_event_hash,
    )


def test_create_and_verify_two_event_tenant_chain() -> None:
    """An ordered same-tenant chain verifies from genesis through its current head."""
    first = _event()
    second = _event(sequence_number=2, previous_event_hash=first.event_hash)

    verify_audit_chain((first, second), tenant_id=TENANT_ID)

    assert first.previous_event_hash == GENESIS_EVENT_HASH
    assert second.previous_event_hash == first.event_hash
    assert len(first.event_hash) == 64
    assert first.event_hash == recompute_event_hash(first)
    assert second.to_dict()["event_hash"] == second.event_hash


def test_canonical_summary_order_produces_identical_event_hash() -> None:
    """JSON object insertion order cannot alter the cryptographic event identity."""
    left = _event(summary={"after": {"revision": 2}, "before": {"revision": 1}})
    right = _event(summary={"before": {"revision": 1}, "after": {"revision": 2}})

    assert left.summary == right.summary
    assert left.event_hash == right.event_hash


@pytest.mark.parametrize(
    "mutation",
    [
        lambda first, second: (replace(first, summary={"policy_revision": 99}), second),
        lambda first, second: (second, first),
        lambda first, second: (second,),
        lambda first, second: (
            first,
            replace(second, previous_event_hash=GENESIS_EVENT_HASH),
        ),
        lambda first, second: (
            first,
            replace(second, tenant_id=TENANT_ID + 1),
        ),
    ],
)
def test_chain_verification_detects_mutation_reorder_deletion_and_substitution(
    mutation,
) -> None:
    """Audit verification fails closed for realistic tampering and tenant substitution."""
    first = _event()
    second = _event(sequence_number=2, previous_event_hash=first.event_hash)

    with pytest.raises(ValueError, match="audit chain"):
        verify_audit_chain(mutation(first, second), tenant_id=TENANT_ID)


def test_secret_and_customer_evidence_fields_are_redacted_before_hashing() -> None:
    """Audit summaries preserve posture metadata while excluding secrets and raw evidence."""
    summary = sanitize_audit_summary(
        {
            "api_key": "agk_super_secret",
            "authorization": "Bearer should-not-appear",
            "webhook_url": "https://user:pass@hooks.example/x?token=hidden",
            "findings": [{"snippet": "customer secret"}],
            "safe": {
                "role": "owner",
                "message": "Bearer another-secret",
                "record_count": 7,
            },
        }
    )
    rendered = json.dumps(summary, sort_keys=True)

    assert summary["safe"]["role"] == "owner"
    assert summary["safe"]["record_count"] == 7
    assert summary["api_key"] == "[REDACTED]"
    assert summary["safe"]["message"] == "[REDACTED]"
    for forbidden in (
        "agk_super_secret",
        "should-not-appear",
        "user:pass",
        "token=hidden",
        "customer secret",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"tenant_id": 0}, "tenant_id"),
        ({"sequence_number": 0}, "sequence_number"),
        ({"event_id": ""}, "event_id"),
        ({"event_type": "Retention Policy Updated"}, "event_type"),
        ({"actor_id": ""}, "actor_id"),
        ({"request_id": ""}, "request_id"),
        ({"occurred_at": "2026-08-04"}, "occurred_at"),
        ({"previous_event_hash": "not-a-hash"}, "previous_event_hash"),
        ({"summary": {"ratio": 0.5}}, "unsupported audit value"),
        ({"summary": {1: "not-a-string-key"}}, "string keys"),
    ],
)
def test_audit_event_rejects_noncanonical_identity_and_summary_inputs(
    overrides: dict[str, object],
    match: str,
) -> None:
    """Every value contributing to an event hash has one canonical representation."""
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "sequence_number": 1,
        "event_id": "audit-event-1",
        "event_type": "retention.policy.updated",
        "actor_id": "owner-key-7",
        "request_id": "request-1",
        "occurred_at": OCCURRED_AT,
        "summary": {"policy_revision": 1},
        "previous_event_hash": GENESIS_EVENT_HASH,
    }
    values.update(overrides)

    with pytest.raises(ValueError, match=match):
        create_audit_event(**values)


def test_audit_summary_has_bounded_depth_and_encoded_size() -> None:
    """Hostile nested or oversized metadata cannot exhaust the audit pipeline."""
    too_deep: dict[str, object] = {"leaf": "value"}
    for index in range(10):
        too_deep = {f"level_{index}": too_deep}

    with pytest.raises(ValueError, match="depth"):
        sanitize_audit_summary(too_deep)
    with pytest.raises(ValueError, match="size"):
        sanitize_audit_summary({"note": "x" * 20_000})


def test_empty_chain_is_valid_and_non_event_members_are_rejected() -> None:
    """A tenant may have no events, but an invalid collection member is never ignored."""
    verify_audit_chain((), tenant_id=TENANT_ID)

    with pytest.raises(ValueError, match="AuditEvent"):
        verify_audit_chain((object(),), tenant_id=TENANT_ID)
