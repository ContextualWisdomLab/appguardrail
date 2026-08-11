"""Model tenant retention policy, deterministic purge previews, and receipts.

The module contains no database or HTTP dependency. AppGuardrail's embedded
control plane, organization services, and naruon modules can therefore share the
same policy bounds, cutoff calculations, stale-preview checks, and evidence
hashes while keeping persistence and authorization behind separate adapters.

Default durations are product defaults, not a claim of legal compliance. Each
buyer must map retention to applicable law, contracts, legal holds, and incident
response requirements.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


RETENTION_CATEGORIES = (
    "scan_history",
    "audit_events",
    "access_key_metadata",
    "webhook_metadata",
    "suppression_evidence",
)
DEFAULT_RETENTION_DAYS = {
    "scan_history": 90,
    "audit_events": 365,
    "access_key_metadata": 365,
    "webhook_metadata": 365,
    "suppression_evidence": 365,
}
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 3650
_DURATION_FIELDS = {
    "scan_history_days": "scan_history",
    "audit_event_days": "audit_events",
    "access_key_metadata_days": "access_key_metadata",
    "webhook_metadata_days": "webhook_metadata",
    "suppression_evidence_days": "suppression_evidence",
}
_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class RetentionPolicyConflict(ValueError):
    """Raised when an update uses a stale optimistic-concurrency revision."""


class StalePurgePreview(ValueError):
    """Raised when policy or legal-hold state changed after preview creation."""


def _canonical_utc(value: str, field_name: str) -> str:
    """Return one valid UTC timestamp with whole-second precision."""
    timestamp = str(value or "").strip()
    try:
        parsed = datetime.strptime(timestamp, _UTC_FORMAT)
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DDTHH:MM:SSZ") from exc
    return parsed.strftime(_UTC_FORMAT)


def _identifier(value: str, field_name: str) -> str:
    """Return a non-empty bounded identifier without control characters."""
    identifier = str(value or "").strip()
    if not identifier or len(identifier) > 256 or any(ord(char) < 32 for char in identifier):
        raise ValueError(f"{field_name} must be a non-empty bounded identifier")
    return identifier


def _positive_integer(value: Any, field_name: str) -> int:
    """Return one positive non-Boolean integer."""
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _nonnegative_integer(value: Any, field_name: str) -> int:
    """Return one non-negative non-Boolean integer."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _retention_days(value: Any, field_name: str) -> int:
    """Return a bounded duration suitable for deterministic retention policy."""
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < MIN_RETENTION_DAYS
        or value > MAX_RETENTION_DAYS
    ):
        raise ValueError(
            f"{field_name} must be an integer from {MIN_RETENTION_DAYS} through "
            f"{MAX_RETENTION_DAYS}"
        )
    return value


@dataclass(frozen=True)
class RetentionPolicy:
    """One revisioned tenant policy with an explicit duration for every data class."""

    tenant_id: int
    revision: int
    scan_history_days: int
    audit_event_days: int
    access_key_metadata_days: int
    webhook_metadata_days: int
    suppression_evidence_days: int
    updated_at: str
    updated_by: str

    def __post_init__(self) -> None:
        """Validate and canonicalize identity, duration, and audit metadata."""
        _positive_integer(self.tenant_id, "tenant_id")
        _positive_integer(self.revision, "revision")
        for field_name in _DURATION_FIELDS:
            _retention_days(getattr(self, field_name), field_name)
        object.__setattr__(self, "updated_at", _canonical_utc(self.updated_at, "updated_at"))
        object.__setattr__(self, "updated_by", _identifier(self.updated_by, "updated_by"))

    @classmethod
    def default(
        cls,
        *,
        tenant_id: int,
        updated_at: str,
        updated_by: str,
    ) -> "RetentionPolicy":
        """Create the documented product defaults for a newly configured tenant."""
        return cls(
            tenant_id=tenant_id,
            revision=1,
            scan_history_days=DEFAULT_RETENTION_DAYS["scan_history"],
            audit_event_days=DEFAULT_RETENTION_DAYS["audit_events"],
            access_key_metadata_days=DEFAULT_RETENTION_DAYS["access_key_metadata"],
            webhook_metadata_days=DEFAULT_RETENTION_DAYS["webhook_metadata"],
            suppression_evidence_days=DEFAULT_RETENTION_DAYS["suppression_evidence"],
            updated_at=updated_at,
            updated_by=updated_by,
        )

    def retention_days(self) -> dict[str, int]:
        """Return category-keyed duration values in the public deterministic order."""
        return {
            category: getattr(self, field_name)
            for field_name, category in _DURATION_FIELDS.items()
        }

    def cutoffs(self, *, as_of: str) -> dict[str, str]:
        """Return the inclusive age cutoff for every data class at one UTC instant."""
        instant = datetime.strptime(_canonical_utc(as_of, "as_of"), _UTC_FORMAT).replace(
            tzinfo=timezone.utc
        )
        return {
            category: (instant - timedelta(days=days)).strftime(_UTC_FORMAT)
            for category, days in self.retention_days().items()
        }

    def to_dict(self) -> dict[str, Any]:
        """Return one machine-readable policy snapshot without hidden defaults."""
        return {
            "tenant_id": self.tenant_id,
            "revision": self.revision,
            "retention_days": self.retention_days(),
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
        }


def update_retention_policy(
    policy: RetentionPolicy,
    *,
    expected_revision: int,
    changes: Mapping[str, Any],
    updated_at: str,
    updated_by: str,
) -> RetentionPolicy:
    """Apply one owner-authorized revision using optimistic concurrency."""
    if not isinstance(policy, RetentionPolicy):
        raise ValueError("policy must be a RetentionPolicy")
    normalized_expected_revision = _positive_integer(
        expected_revision,
        "expected_revision",
    )
    if normalized_expected_revision != policy.revision:
        raise RetentionPolicyConflict(
            "retention policy revision conflict: expected "
            f"{normalized_expected_revision}, current {policy.revision}"
        )
    if not isinstance(changes, Mapping):
        raise ValueError("changes must be an object")
    unsupported = set(changes) - set(_DURATION_FIELDS)
    if unsupported:
        raise ValueError(
            "unsupported policy field: " + ", ".join(sorted(str(item) for item in unsupported))
        )
    validated_changes = {
        field_name: _retention_days(value, field_name)
        for field_name, value in changes.items()
    }
    return replace(
        policy,
        revision=policy.revision + 1,
        updated_at=_canonical_utc(updated_at, "updated_at"),
        updated_by=_identifier(updated_by, "updated_by"),
        **validated_changes,
    )


def _validated_counts(
    counts: Mapping[str, Any],
    *,
    field_name: str,
) -> dict[str, int]:
    """Return exactly one non-negative count for each retention category."""
    if not isinstance(counts, Mapping):
        raise ValueError(f"{field_name} count mapping is required")
    if set(counts) != set(RETENTION_CATEGORIES):
        raise ValueError(f"{field_name} count mapping must contain every category exactly once")
    return {
        category: _nonnegative_integer(counts[category], f"{field_name} count")
        for category in RETENTION_CATEGORIES
    }


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    """Return a SHA-256 digest over deterministic UTF-8 JSON bytes."""
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _preview_payload(
    *,
    preview_id: str,
    tenant_id: int,
    policy_revision: int,
    legal_hold_revision: int,
    created_at: str,
    cutoffs: Mapping[str, str],
    eligible_counts: Mapping[str, Any],
    held_counts: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and return the exact payload committed by a purge preview hash."""
    normalized_eligible = _validated_counts(
        eligible_counts,
        field_name="eligible",
    )
    normalized_held = _validated_counts(held_counts, field_name="held")
    for category in RETENTION_CATEGORIES:
        if normalized_held[category] > normalized_eligible[category]:
            raise ValueError("held count cannot exceed eligible count")
    if not isinstance(cutoffs, Mapping) or set(cutoffs) != set(RETENTION_CATEGORIES):
        raise ValueError("cutoff mapping must contain every retention category")
    normalized_cutoffs = {
        category: _canonical_utc(cutoffs[category], f"{category} cutoff")
        for category in RETENTION_CATEGORIES
    }
    return {
        "preview_id": _identifier(preview_id, "preview_id"),
        "tenant_id": _positive_integer(tenant_id, "tenant_id"),
        "policy_revision": _positive_integer(policy_revision, "policy_revision"),
        "legal_hold_revision": _nonnegative_integer(
            legal_hold_revision,
            "legal_hold_revision",
        ),
        "created_at": _canonical_utc(created_at, "created_at"),
        "cutoffs": normalized_cutoffs,
        "eligible_counts": normalized_eligible,
        "held_counts": normalized_held,
    }


@dataclass(frozen=True)
class PurgePreview:
    """A hash-bound, non-destructive count snapshot for one tenant purge decision."""

    preview_id: str
    tenant_id: int
    policy_revision: int
    legal_hold_revision: int
    created_at: str
    cutoffs: dict[str, str]
    eligible_counts: dict[str, int]
    held_counts: dict[str, int]
    preview_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Return a non-secret preview representation suitable for approval workflows."""
        return {
            "preview_id": self.preview_id,
            "tenant_id": self.tenant_id,
            "policy_revision": self.policy_revision,
            "legal_hold_revision": self.legal_hold_revision,
            "created_at": self.created_at,
            "cutoffs": dict(self.cutoffs),
            "eligible_counts": dict(self.eligible_counts),
            "held_counts": dict(self.held_counts),
            "preview_hash": self.preview_hash,
        }


def build_purge_preview(
    policy: RetentionPolicy,
    *,
    preview_id: str,
    legal_hold_revision: int,
    created_at: str,
    eligible_counts: Mapping[str, Any],
    held_counts: Mapping[str, Any],
) -> PurgePreview:
    """Build one deterministic preview bound to policy, holds, cutoffs, and counts."""
    if not isinstance(policy, RetentionPolicy):
        raise ValueError("policy must be a RetentionPolicy")
    payload = _preview_payload(
        preview_id=preview_id,
        tenant_id=policy.tenant_id,
        policy_revision=policy.revision,
        legal_hold_revision=legal_hold_revision,
        created_at=created_at,
        cutoffs=policy.cutoffs(as_of=created_at),
        eligible_counts=eligible_counts,
        held_counts=held_counts,
    )
    return PurgePreview(**payload, preview_hash=_canonical_hash(payload))


def verify_purge_preview(
    preview: PurgePreview,
    *,
    policy_revision: int,
    legal_hold_revision: int,
) -> None:
    """Reject tampered previews and previews stale against current tenant state."""
    if not isinstance(preview, PurgePreview):
        raise ValueError("preview must be a PurgePreview")
    normalized_policy_revision = _positive_integer(
        policy_revision,
        "policy_revision",
    )
    normalized_legal_hold_revision = _nonnegative_integer(
        legal_hold_revision,
        "legal_hold_revision",
    )
    payload = _preview_payload(
        preview_id=preview.preview_id,
        tenant_id=preview.tenant_id,
        policy_revision=preview.policy_revision,
        legal_hold_revision=preview.legal_hold_revision,
        created_at=preview.created_at,
        cutoffs=preview.cutoffs,
        eligible_counts=preview.eligible_counts,
        held_counts=preview.held_counts,
    )
    if preview.preview_hash != _canonical_hash(payload):
        raise ValueError("purge preview hash does not match its payload")
    if (
        preview.policy_revision != normalized_policy_revision
        or preview.legal_hold_revision != normalized_legal_hold_revision
    ):
        raise StalePurgePreview("purge preview is stale against current tenant state")


@dataclass(frozen=True)
class PurgeReceipt:
    """Non-secret evidence that one exact preview was executed atomically."""

    receipt_id: str
    tenant_id: int
    preview_id: str
    preview_hash: str
    policy_revision: int
    legal_hold_revision: int
    cutoffs: dict[str, str]
    deleted_counts: dict[str, int]
    held_counts: dict[str, int]
    executed_at: str
    audit_event_id: str

    def to_dict(self) -> dict[str, Any]:
        """Return the machine-readable receipt without deleted customer records."""
        return {
            "receipt_id": self.receipt_id,
            "tenant_id": self.tenant_id,
            "preview_id": self.preview_id,
            "preview_hash": self.preview_hash,
            "policy_revision": self.policy_revision,
            "legal_hold_revision": self.legal_hold_revision,
            "cutoffs": dict(self.cutoffs),
            "deleted_counts": dict(self.deleted_counts),
            "held_counts": dict(self.held_counts),
            "executed_at": self.executed_at,
            "audit_event_id": self.audit_event_id,
        }


def create_purge_receipt(
    preview: PurgePreview,
    *,
    policy_revision: int,
    legal_hold_revision: int,
    receipt_id: str,
    executed_at: str,
    audit_event_id: str,
) -> PurgeReceipt:
    """Create completion evidence after an explicit final current-state check."""
    if not isinstance(preview, PurgePreview):
        raise ValueError("preview must be a PurgePreview")
    verify_purge_preview(
        preview,
        policy_revision=policy_revision,
        legal_hold_revision=legal_hold_revision,
    )
    normalized_executed_at = _canonical_utc(executed_at, "executed_at")
    if normalized_executed_at < preview.created_at:
        raise ValueError("executed_at cannot precede purge preview creation")
    return PurgeReceipt(
        receipt_id=_identifier(receipt_id, "receipt_id"),
        tenant_id=preview.tenant_id,
        preview_id=preview.preview_id,
        preview_hash=preview.preview_hash,
        policy_revision=preview.policy_revision,
        legal_hold_revision=preview.legal_hold_revision,
        cutoffs=dict(preview.cutoffs),
        deleted_counts={
            category: preview.eligible_counts[category] - preview.held_counts[category]
            for category in RETENTION_CATEGORIES
        },
        held_counts=dict(preview.held_counts),
        executed_at=normalized_executed_at,
        audit_event_id=_identifier(audit_event_id, "audit_event_id"),
    )
