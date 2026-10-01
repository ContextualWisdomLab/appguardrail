"""Fail-closed comparison of live GitHub Code Scanning analysis coverage."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Iterable, Literal


SnapshotStatus = Literal["ok", "unknown"]
AssessmentStatus = Literal["clean", "drift", "unknown"]

_MAX_DIMENSION_CHARS = 500
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_VOLATILE_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE)
_VOLATILE_REF_RE = re.compile(
    r"\brefs/(?:heads/[^\s,;]+|pull/[1-9][0-9]*/(?:merge|head))\b",
    re.IGNORECASE,
)
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True, order=True)
class AnalysisIdentity:
    """Stable tool, category, and matrix identity for one SARIF analysis stream."""

    tool_name: str
    tool_guid: str
    category: str
    analysis_key: str
    environment: str


@dataclass(frozen=True)
class AnalysisEvidence:
    """Normalized evidence for one GitHub Code Scanning analysis execution."""

    identity: AnalysisIdentity
    analysis_id: int
    ref: str
    commit_sha: str
    created_at: str
    error: str
    warning: str

    @property
    def healthy(self) -> bool:
        """Return whether GitHub reported no execution error for the analysis."""
        return not self.error


@dataclass(frozen=True)
class AnalysisSnapshot:
    """Complete or explicitly unknown analysis evidence for one comparison scope."""

    scope: str
    status: SnapshotStatus
    complete: bool
    analyses: tuple[AnalysisEvidence, ...]
    reason: str = ""


@dataclass(frozen=True)
class DriftAssessment:
    """Comparison result between a healthy base snapshot and an exact PR snapshot."""

    status: AssessmentStatus
    missing: tuple[AnalysisIdentity, ...] = ()
    errored: tuple[AnalysisEvidence, ...] = ()
    warnings: tuple[AnalysisEvidence, ...] = ()
    reason: str = ""


def _required_text(value: Any, field: str) -> str:
    """Return one required bounded text field or raise a fail-closed error."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value.strip()


def _optional_text(value: Any) -> str:
    """Return a bounded optional text value without accepting container coercion."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("optional analysis text must be a string or null")
    return value.strip()[:_MAX_DIMENSION_CHARS]


def _stable_dimension(value: Any) -> str:
    """Remove volatile refs and commit SHAs while preserving matrix dimensions."""
    text = _optional_text(value)
    text = _VOLATILE_REF_RE.sub("<ref>", text)
    text = _VOLATILE_SHA_RE.sub("<sha>", text)
    return _WHITESPACE_RE.sub(" ", text).strip()[:_MAX_DIMENSION_CHARS]


def _normalized_timestamp(value: Any) -> str:
    """Validate an offset-aware GitHub timestamp and return canonical UTC text."""
    text = _required_text(value, "created_at")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("created_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_analysis(payload: dict[str, Any]) -> AnalysisEvidence:
    """Normalize one GitHub analysis payload using the supported nested tool fields."""
    if not isinstance(payload, dict):
        raise ValueError("analysis payload must be an object")
    analysis_id = payload.get("id")
    if not isinstance(analysis_id, int) or isinstance(analysis_id, bool) or analysis_id <= 0:
        raise ValueError("id must be a positive integer")

    tool = payload.get("tool")
    if not isinstance(tool, dict):
        raise ValueError("tool.name must be provided in the nested tool object")
    tool_name = _required_text(tool.get("name"), "tool.name").casefold()
    tool_guid = _optional_text(tool.get("guid")).casefold()
    category = _optional_text(payload.get("category")).casefold() or "default"

    ref = _required_text(payload.get("ref"), "ref")
    commit_sha = _required_text(payload.get("commit_sha"), "commit_sha").lower()
    if not _COMMIT_SHA_RE.fullmatch(commit_sha):
        raise ValueError("commit_sha must be a 40-character hexadecimal SHA")

    identity = AnalysisIdentity(
        tool_name=tool_name,
        tool_guid=tool_guid,
        category=category,
        analysis_key=_stable_dimension(payload.get("analysis_key")),
        environment=_stable_dimension(payload.get("environment")),
    )
    return AnalysisEvidence(
        identity=identity,
        analysis_id=analysis_id,
        ref=ref,
        commit_sha=commit_sha,
        created_at=_normalized_timestamp(payload.get("created_at")),
        error=_optional_text(payload.get("error")),
        warning=_optional_text(payload.get("warning")),
    )


def build_snapshot(
    payloads: Iterable[dict[str, Any]],
    *,
    scope: str,
    expected_refs: Iterable[str],
    expected_commit_shas: Iterable[str] = (),
    complete: bool = True,
    unknown_reason: str = "",
) -> AnalysisSnapshot:
    """Build the latest exact analysis set or an explicit fail-closed unknown state."""
    normalized_scope = str(scope or "").strip() or "unknown"
    reason = str(unknown_reason or "").strip()
    if not complete or reason:
        return AnalysisSnapshot(
            scope=normalized_scope,
            status="unknown",
            complete=False,
            analyses=(),
            reason=reason or "incomplete_pagination",
        )

    refs = {str(ref).strip() for ref in expected_refs if str(ref).strip()}
    commits = {str(sha).strip().lower() for sha in expected_commit_shas if str(sha).strip()}
    if any(not _COMMIT_SHA_RE.fullmatch(sha) for sha in commits):
        return AnalysisSnapshot(
            scope=normalized_scope,
            status="unknown",
            complete=False,
            analyses=(),
            reason="invalid_expected_commit_sha",
        )

    raw_items = list(payloads)
    exact: list[AnalysisEvidence] = []
    try:
        for payload in raw_items:
            evidence = normalize_analysis(payload)
            if refs and evidence.ref not in refs:
                continue
            if commits and evidence.commit_sha not in commits:
                continue
            exact.append(evidence)
    except (TypeError, ValueError):
        return AnalysisSnapshot(
            scope=normalized_scope,
            status="unknown",
            complete=False,
            analyses=(),
            reason="malformed_analysis_payload",
        )

    if raw_items and not exact:
        return AnalysisSnapshot(
            scope=normalized_scope,
            status="unknown",
            complete=False,
            analyses=(),
            reason="no_exact_analysis_evidence",
        )

    latest: dict[AnalysisIdentity, AnalysisEvidence] = {}
    for evidence in exact:
        current = latest.get(evidence.identity)
        if current is None or (evidence.created_at, evidence.analysis_id) > (
            current.created_at,
            current.analysis_id,
        ):
            latest[evidence.identity] = evidence
    return AnalysisSnapshot(
        scope=normalized_scope,
        status="ok",
        complete=True,
        analyses=tuple(latest[identity] for identity in sorted(latest)),
    )


def compare_snapshots(
    base: AnalysisSnapshot, current: AnalysisSnapshot
) -> DriftAssessment:
    """Compare complete snapshots without inferring drift from unknown evidence."""
    if base.status != "ok" or current.status != "ok" or not base.complete or not current.complete:
        reason = base.reason or current.reason or "incomplete_analysis_evidence"
        return DriftAssessment(status="unknown", reason=reason)

    healthy_base = {
        evidence.identity: evidence for evidence in base.analyses if evidence.healthy
    }
    if not healthy_base:
        return DriftAssessment(status="unknown", reason="no_healthy_base_analysis")

    current_by_identity = {evidence.identity: evidence for evidence in current.analyses}

    missing_list, errored_list, warnings_list = [], [], []
    for identity in sorted(healthy_base):
        if identity not in current_by_identity:
            missing_list.append(identity)
        else:
            current_evidence = current_by_identity[identity]
            if not current_evidence.healthy:
                errored_list.append(current_evidence)
            if current_evidence.warning:
                warnings_list.append(current_evidence)
    missing, errored, warnings = tuple(missing_list), tuple(errored_list), tuple(warnings_list)

    if missing or errored:
        return DriftAssessment(
            status="drift",
            missing=missing,
            errored=errored,
            warnings=warnings,
            reason="missing_or_unhealthy_current_analysis",
        )
    return DriftAssessment(status="clean", warnings=warnings)
