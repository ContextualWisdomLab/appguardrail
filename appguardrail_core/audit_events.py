"""Create and verify tenant-scoped, tamper-evident audit event chains.

The module is dependency-free so AppGuardrail, organization services, and naruon
modules can share one deterministic event identity. Hash chaining is evidence of
tampering, not a claim that storage is physically immutable; persistence layers
must additionally enforce append-only writes and durable access controls.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping


GENESIS_EVENT_HASH = "0" * 64
MAX_AUDIT_SUMMARY_BYTES = 16_384
MAX_AUDIT_SUMMARY_DEPTH = 8
_EVENT_TYPE_RE = re.compile(r"\A[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_HASH_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_UTC_TIMESTAMP_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_SENSITIVE_KEY_PARTS = (
    "api_key",
    "authorization",
    "credential",
    "findings",
    "password",
    "raw_evidence",
    "secret",
    "snippet",
    "token",
    "webhook_url",
)
_SENSITIVE_TEXT_RE = re.compile(
    r"(?i)(?:\bbearer\b|\bauthorization\b|\bapi[ _-]?key\b|"
    r"\bpassword\b|\bsecret\b|\btoken\b|\bagk_[A-Za-z0-9_-]+)"
)


def _canonical_utc(value: str, field_name: str) -> str:
    """Return a validated UTC timestamp serialized at whole-second precision."""
    timestamp = str(value or "").strip()
    if not _UTC_TIMESTAMP_RE.fullmatch(timestamp):
        raise ValueError(f"{field_name} must use YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DDTHH:MM:SSZ") from exc
    return timestamp


def _identifier(value: str, field_name: str) -> str:
    """Return one non-empty, bounded identifier without control characters."""
    identifier = str(value or "").strip()
    if not identifier or len(identifier) > 256 or any(ord(char) < 32 for char in identifier):
        raise ValueError(f"{field_name} must be a non-empty bounded identifier")
    return identifier


def _sensitive_key(key: str) -> bool:
    """Return whether a key names secret or raw customer evidence material."""
    normalized = key.casefold().replace("-", "_").replace(" ", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _sanitize_value(value: Any, *, depth: int) -> Any:
    """Recursively normalize one JSON value while redacting secret-like text."""
    if depth > MAX_AUDIT_SUMMARY_DEPTH:
        raise ValueError("audit summary exceeds maximum depth")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        raise ValueError("unsupported audit value: floating-point numbers")
    if isinstance(value, str):
        return "[REDACTED]" if _SENSITIVE_TEXT_RE.search(value) else value
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise ValueError("audit summary object must use string keys")
            key = raw_key.strip()
            if not key:
                raise ValueError("audit summary object must use non-empty string keys")
            sanitized[key] = (
                "[REDACTED]"
                if _sensitive_key(key)
                else _sanitize_value(child, depth=depth + 1)
            )
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(child, depth=depth + 1) for child in value]
    raise ValueError(f"unsupported audit value: {type(value).__name__}")


def sanitize_audit_summary(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Return bounded canonical JSON metadata with secret-bearing fields redacted.

    Audit summaries are intentionally descriptive rather than forensic payloads.
    Secret keys, authorization data, raw findings, snippets, and secret-like text
    are replaced before hashing so they cannot leak through logs or diligence
    exports.
    """
    if not isinstance(summary, Mapping):
        raise ValueError("audit summary must be an object")
    sanitized = _sanitize_value(summary, depth=0)
    assert isinstance(sanitized, dict)
    encoded = json.dumps(
        sanitized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_AUDIT_SUMMARY_BYTES:
        raise ValueError("audit summary exceeds maximum encoded size")
    return json.loads(encoded.decode("utf-8"))


@dataclass(frozen=True)
class AuditEvent:
    """One canonical event in a tenant-local SHA-256 hash chain."""

    tenant_id: int
    sequence_number: int
    event_id: str
    event_type: str
    actor_id: str
    request_id: str
    occurred_at: str
    summary: dict[str, Any]
    previous_event_hash: str
    event_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Return a machine-readable copy suitable for persistence and export."""
        return {
            "tenant_id": self.tenant_id,
            "sequence_number": self.sequence_number,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "request_id": self.request_id,
            "occurred_at": self.occurred_at,
            "summary": json.loads(json.dumps(self.summary)),
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
        }


def _event_payload(
    *,
    tenant_id: int,
    sequence_number: int,
    event_id: str,
    event_type: str,
    actor_id: str,
    request_id: str,
    occurred_at: str,
    summary: Mapping[str, Any],
    previous_event_hash: str,
) -> dict[str, Any]:
    """Validate and return the exact payload whose bytes define an event hash."""
    if not isinstance(tenant_id, int) or isinstance(tenant_id, bool) or tenant_id <= 0:
        raise ValueError("tenant_id must be a positive integer")
    if (
        not isinstance(sequence_number, int)
        or isinstance(sequence_number, bool)
        or sequence_number <= 0
    ):
        raise ValueError("sequence_number must be a positive integer")
    normalized_event_id = _identifier(event_id, "event_id")
    normalized_event_type = str(event_type or "").strip()
    if not _EVENT_TYPE_RE.fullmatch(normalized_event_type):
        raise ValueError("event_type must use lowercase dot, underscore, or hyphen segments")
    normalized_previous_hash = str(previous_event_hash or "").strip().lower()
    if not _HASH_RE.fullmatch(normalized_previous_hash):
        raise ValueError("previous_event_hash must be a lowercase SHA-256 hex digest")
    return {
        "tenant_id": tenant_id,
        "sequence_number": sequence_number,
        "event_id": normalized_event_id,
        "event_type": normalized_event_type,
        "actor_id": _identifier(actor_id, "actor_id"),
        "request_id": _identifier(request_id, "request_id"),
        "occurred_at": _canonical_utc(occurred_at, "occurred_at"),
        "summary": sanitize_audit_summary(summary),
        "previous_event_hash": normalized_previous_hash,
    }


def _hash_payload(payload: Mapping[str, Any]) -> str:
    """Return the SHA-256 digest of canonical UTF-8 JSON payload bytes."""
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def create_audit_event(
    *,
    tenant_id: int,
    sequence_number: int,
    event_id: str,
    event_type: str,
    actor_id: str,
    request_id: str,
    occurred_at: str,
    summary: Mapping[str, Any],
    previous_event_hash: str = GENESIS_EVENT_HASH,
) -> AuditEvent:
    """Create one validated event whose hash commits to its tenant and predecessor."""
    payload = _event_payload(
        tenant_id=tenant_id,
        sequence_number=sequence_number,
        event_id=event_id,
        event_type=event_type,
        actor_id=actor_id,
        request_id=request_id,
        occurred_at=occurred_at,
        summary=summary,
        previous_event_hash=previous_event_hash,
    )
    return AuditEvent(**payload, event_hash=_hash_payload(payload))


def recompute_event_hash(event: AuditEvent) -> str:
    """Recompute one event hash after revalidating every committed field."""
    if not isinstance(event, AuditEvent):
        raise ValueError("event must be an AuditEvent")
    payload = _event_payload(
        tenant_id=event.tenant_id,
        sequence_number=event.sequence_number,
        event_id=event.event_id,
        event_type=event.event_type,
        actor_id=event.actor_id,
        request_id=event.request_id,
        occurred_at=event.occurred_at,
        summary=event.summary,
        previous_event_hash=event.previous_event_hash,
    )
    return _hash_payload(payload)


def verify_audit_chain(events: Iterable[AuditEvent], *, tenant_id: int) -> None:
    """Validate sequence, tenant isolation, predecessor links, and every event hash."""
    expected_previous_hash = GENESIS_EVENT_HASH
    expected_sequence = 1
    for event in events:
        if not isinstance(event, AuditEvent):
            raise ValueError("audit chain member must be an AuditEvent")
        try:
            if event.tenant_id != tenant_id:
                raise ValueError("tenant mismatch")
            if event.sequence_number != expected_sequence:
                raise ValueError("sequence mismatch")
            if event.previous_event_hash != expected_previous_hash:
                raise ValueError("predecessor mismatch")
            if event.event_hash != recompute_event_hash(event):
                raise ValueError("event hash mismatch")
        except ValueError as exc:
            raise ValueError(f"audit chain invalid at sequence {expected_sequence}: {exc}") from exc
        expected_previous_hash = event.event_hash
        expected_sequence += 1
