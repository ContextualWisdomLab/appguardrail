"""Build non-secret retention and audit posture for buyer diligence.

The module deliberately exports policy and verification posture rather than
customer records, actor identities, request identifiers, finding snippets, or
audit summaries. It is dependency-free and can therefore be reused by the
standalone product and organization services without moving persistence or
authorization authority into the reporting layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from appguardrail_core.audit_events import GENESIS_EVENT_HASH
from appguardrail_core.retention_policy import (
    MAX_RETENTION_DAYS,
    MIN_RETENTION_DAYS,
    RETENTION_CATEGORIES,
    PurgeReceipt,
    RetentionPolicy,
)

AUDIT_CHAIN_STATUSES = ("verified", "unverified", "failed")
_HASH_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _nonnegative_integer(value: Any, field_name: str) -> int:
    """Return one non-negative non-Boolean integer."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _positive_integer(value: Any, field_name: str) -> int:
    """Return one positive non-Boolean integer."""
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _canonical_utc(value: Any, field_name: str) -> str:
    """Return one validated whole-second UTC timestamp."""
    timestamp = str(value or "").strip()
    try:
        parsed = datetime.strptime(timestamp, _UTC_FORMAT)
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DDTHH:MM:SSZ") from exc
    return parsed.strftime(_UTC_FORMAT)


def _hash(value: Any, field_name: str) -> str:
    """Return one canonical lowercase SHA-256 hexadecimal digest."""
    digest = str(value or "").strip()
    if not _HASH_RE.fullmatch(digest):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 hex digest")
    return digest


def _identifier(value: Any, field_name: str) -> str:
    """Return a bounded non-empty identifier without control characters."""
    identifier = str(value or "").strip()
    if not identifier or len(identifier) > 256 or any(ord(char) < 32 for char in identifier):
        raise ValueError(f"{field_name} must be a non-empty bounded identifier")
    return identifier


def _retention_days(values: Mapping[str, Any]) -> dict[str, int]:
    """Validate one complete retention-duration map in canonical category order."""
    if not isinstance(values, Mapping) or set(values) != set(RETENTION_CATEGORIES):
        raise ValueError("retention_days must contain every retention category exactly once")
    normalized: dict[str, int] = {}
    for category in RETENTION_CATEGORIES:
        days = values[category]
        if (
            not isinstance(days, int)
            or isinstance(days, bool)
            or days < MIN_RETENTION_DAYS
            or days > MAX_RETENTION_DAYS
        ):
            raise ValueError(
                f"{category} retention must be an integer from "
                f"{MIN_RETENTION_DAYS} through {MAX_RETENTION_DAYS}"
            )
        normalized[category] = days
    return normalized


def _audit_chain_status(value: Any) -> str:
    """Return one supported explicit audit-chain verification state."""
    status = str(value or "").strip().lower()
    if status not in AUDIT_CHAIN_STATUSES:
        raise ValueError("audit_chain_status must be verified, unverified, or failed")
    return status


@dataclass(frozen=True)
class RetentionAuditPosture:
    """Non-secret buyer-facing snapshot of one tenant's retention controls."""

    policy_revision: int
    retention_days: dict[str, int]
    legal_hold_count: int
    audit_chain_status: str
    audit_event_count: int
    audit_head_hash: str
    verified_at: str
    last_purge_receipt_id: str = ""
    last_purge_executed_at: str = ""
    last_purge_policy_revision: int | None = None
    last_purge_legal_hold_revision: int | None = None

    def __post_init__(self) -> None:
        """Revalidate public construction and canonicalize safe exported values."""
        object.__setattr__(
            self,
            "policy_revision",
            _positive_integer(self.policy_revision, "policy_revision"),
        )
        object.__setattr__(self, "retention_days", _retention_days(self.retention_days))
        object.__setattr__(
            self,
            "legal_hold_count",
            _nonnegative_integer(self.legal_hold_count, "legal_hold_count"),
        )
        object.__setattr__(
            self,
            "audit_chain_status",
            _audit_chain_status(self.audit_chain_status),
        )
        event_count = _nonnegative_integer(self.audit_event_count, "audit_event_count")
        head_hash = _hash(self.audit_head_hash, "audit_head_hash")
        if self.audit_chain_status == "verified":
            if event_count == 0 and head_hash != GENESIS_EVENT_HASH:
                raise ValueError("verified empty audit chain must use the genesis hash")
            if event_count > 0 and head_hash == GENESIS_EVENT_HASH:
                raise ValueError("verified non-empty audit chain cannot use the genesis hash")
        object.__setattr__(self, "audit_event_count", event_count)
        object.__setattr__(self, "audit_head_hash", head_hash)
        object.__setattr__(
            self,
            "verified_at",
            _canonical_utc(self.verified_at, "verified_at"),
        )

        has_receipt = bool(self.last_purge_receipt_id)
        receipt_fields = (
            self.last_purge_executed_at,
            self.last_purge_policy_revision,
            self.last_purge_legal_hold_revision,
        )
        if has_receipt:
            object.__setattr__(
                self,
                "last_purge_receipt_id",
                _identifier(self.last_purge_receipt_id, "last_purge_receipt_id"),
            )
            object.__setattr__(
                self,
                "last_purge_executed_at",
                _canonical_utc(self.last_purge_executed_at, "last_purge_executed_at"),
            )
            object.__setattr__(
                self,
                "last_purge_policy_revision",
                _positive_integer(
                    self.last_purge_policy_revision,
                    "last_purge_policy_revision",
                ),
            )
            object.__setattr__(
                self,
                "last_purge_legal_hold_revision",
                _nonnegative_integer(
                    self.last_purge_legal_hold_revision,
                    "last_purge_legal_hold_revision",
                ),
            )
        elif any(value not in ("", None) for value in receipt_fields):
            raise ValueError("last purge fields require last_purge_receipt_id")

    @property
    def evidence_status(self) -> str:
        """Return ``verified`` only for an explicitly verified audit chain."""
        return "verified" if self.audit_chain_status == "verified" else "incomplete"

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic non-secret posture suitable for diligence export."""
        last_purge: dict[str, Any] | None = None
        if self.last_purge_receipt_id:
            last_purge = {
                "receipt_id": self.last_purge_receipt_id,
                "executed_at": self.last_purge_executed_at,
                "policy_revision": self.last_purge_policy_revision,
                "legal_hold_revision": self.last_purge_legal_hold_revision,
            }
        return {
            "evidence_status": self.evidence_status,
            "policy_revision": self.policy_revision,
            "retention_days": dict(self.retention_days),
            "legal_hold_count": self.legal_hold_count,
            "audit_chain": {
                "status": self.audit_chain_status,
                "event_count": self.audit_event_count,
                "head_hash": self.audit_head_hash,
            },
            "last_purge": last_purge,
            "verified_at": self.verified_at,
        }


def build_retention_audit_posture(
    policy: RetentionPolicy,
    *,
    legal_hold_count: int,
    audit_event_count: int,
    audit_chain_status: str,
    audit_head_hash: str,
    verified_at: str,
    last_purge_receipt: PurgeReceipt | None = None,
) -> RetentionAuditPosture:
    """Build one source-bound safe snapshot from current policy and audit evidence.

    ``last_purge_receipt`` may predate the current policy revision, so its own
    revisions are retained rather than forced to match the current policy. A
    cross-tenant receipt is rejected before any buyer-facing payload is built.
    """
    if not isinstance(policy, RetentionPolicy):
        raise ValueError("policy must be a RetentionPolicy")

    receipt_id = ""
    receipt_executed_at = ""
    receipt_policy_revision: int | None = None
    receipt_legal_hold_revision: int | None = None
    if last_purge_receipt is not None:
        if not isinstance(last_purge_receipt, PurgeReceipt):
            raise ValueError("last_purge_receipt must be a PurgeReceipt")
        if last_purge_receipt.tenant_id != policy.tenant_id:
            raise ValueError("last purge receipt tenant does not match policy tenant")
        receipt_id = _identifier(last_purge_receipt.receipt_id, "receipt_id")
        receipt_executed_at = _canonical_utc(last_purge_receipt.executed_at, "executed_at")
        receipt_policy_revision = _positive_integer(
            last_purge_receipt.policy_revision,
            "receipt policy_revision",
        )
        receipt_legal_hold_revision = _nonnegative_integer(
            last_purge_receipt.legal_hold_revision,
            "receipt legal_hold_revision",
        )

    return RetentionAuditPosture(
        policy_revision=policy.revision,
        retention_days=policy.retention_days(),
        legal_hold_count=legal_hold_count,
        audit_chain_status=audit_chain_status,
        audit_event_count=audit_event_count,
        audit_head_hash=audit_head_hash,
        verified_at=verified_at,
        last_purge_receipt_id=receipt_id,
        last_purge_executed_at=receipt_executed_at,
        last_purge_policy_revision=receipt_policy_revision,
        last_purge_legal_hold_revision=receipt_legal_hold_revision,
    )
