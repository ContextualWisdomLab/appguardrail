"""Defensive checkpoint contracts for tenant-local audit chains."""

from __future__ import annotations

import pytest

from appguardrail_core.audit_events import (
    GENESIS_EVENT_HASH,
    create_audit_event,
    verify_audit_chain,
)


TENANT_ID = 41
OCCURRED_AT = "2026-08-04T12:10:00Z"


def _event(*, sequence_number: int, previous_event_hash: str):
    """Return one deterministic audit event for checkpoint edge tests."""
    return create_audit_event(
        tenant_id=TENANT_ID,
        sequence_number=sequence_number,
        event_id=f"audit-event-{sequence_number}",
        event_type="retention.policy.updated",
        actor_id="owner-key-7",
        request_id=f"request-{sequence_number}",
        occurred_at=OCCURRED_AT,
        summary={"policy_revision": sequence_number},
        previous_event_hash=previous_event_hash,
    )


@pytest.mark.parametrize(
    ("arguments", "match"),
    [
        ({"expected_event_count": True}, "expected_event_count"),
        ({"expected_event_count": -1}, "expected_event_count"),
        ({"expected_head_hash": "not-a-hash"}, "expected_head_hash"),
    ],
)
def test_checkpoint_inputs_reject_noncanonical_values(
    arguments: dict[str, object],
    match: str,
) -> None:
    """Trusted checkpoint identity cannot use Boolean, negative, or malformed values."""
    with pytest.raises(ValueError, match=match):
        verify_audit_chain((), tenant_id=TENANT_ID, **arguments)


def test_head_checkpoint_detects_tail_substitution_at_the_same_count() -> None:
    """A trusted head digest detects a truncated or substituted chain of equal length."""
    first = _event(sequence_number=1, previous_event_hash=GENESIS_EVENT_HASH)
    second = _event(sequence_number=2, previous_event_hash=first.event_hash)

    with pytest.raises(ValueError, match="checkpoint head hash"):
        verify_audit_chain(
            (first,),
            tenant_id=TENANT_ID,
            expected_event_count=1,
            expected_head_hash=second.event_hash,
        )
