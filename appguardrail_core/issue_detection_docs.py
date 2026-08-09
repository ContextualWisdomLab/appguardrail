"""Validate the canonical documentation graph for issue-derived detection.

The validator treats documentation status as release evidence rather than
marketing prose. It resolves every declared artifact, checks diagram-as-code
coverage, binds inventory counts to the packaged detector registry, and rejects
claims of protected-main completion without protected-main operational proof.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping


_MANIFEST_SCHEMA = "appguardrail.issue-detection-documentation.v1"
_REGISTRY_SCHEMA = "appguardrail.issue-detection-registry.v1"
_REQUIRED_ROLES = (
    "adr_index",
    "architecture",
    "erd",
    "incident_runbook",
    "operability",
    "prd",
    "test_strategy",
    "threat_model",
    "traceability",
    "trd",
    "uml",
)
_ALLOWED_ARTIFACT_STATES = {
    "current",
    "partial",
    "stale",
}
_ALLOWED_CAPABILITY_STATES = {
    "accepted_architecture",
    "active_pr",
    "implemented_on_protected_main",
    "missing",
    "partial",
    "planned",
    "research_only",
    "superseded",
}
_REQUIRED_CAPABILITIES = {
    "family_adapter_coverage",
    "inventory_coverage",
    "per_issue_cause_binding",
    "protected_main_operational_proof",
    "source_result_instrumentation",
}
_REQUIRED_DIAGRAMS = {
    "architecture": {"flowchart"},
    "erd": {"erDiagram"},
    "uml": {"flowchart", "sequenceDiagram", "stateDiagram"},
}
_MERMAID_FENCE_RE = re.compile(
    r"(?ms)^\x60\x60\x60mermaid\s*\n"
    r"\s*(flowchart|graph|sequenceDiagram|stateDiagram(?:-v2)?|erDiagram)\b"
)


@dataclass(frozen=True)
class DocumentationAudit:
    """Validated documentation and implementation-status evidence."""

    artifact_count: int
    capability_states: dict[str, str]
    cause_bound_issue_count: int
    claim_count: int
    detector_family_count: int
    diagram_kinds: tuple[str, ...]
    direct_detector_efficacy_validated_claim_count: int
    issue_count: int
    protected_main_operational_issue_count: int
    unique_claim_semantics_count: int


def _require(condition: bool, message: str) -> None:
    """Raise a stable validation error when one contract condition is false."""
    if not condition:
        raise ValueError(message)


def _load_object(path: Path, label: str) -> Mapping[str, Any]:
    """Load one UTF-8 JSON object and reject arrays or scalar documents."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to load {label}: {path}") from exc
    _require(isinstance(payload, Mapping), f"{label} must be a JSON object")
    return payload


def _resolve_declared_path(root: Path, value: Any) -> Path:
    """Resolve a repository-relative path without permitting traversal."""
    _require(isinstance(value, str) and bool(value), "artifact path must be non-empty")
    relative = Path(value)
    _require(
        not relative.is_absolute() and ".." not in relative.parts,
        f"artifact path escapes repository root: {value}",
    )
    return root / relative


def _diagram_kinds(document: str) -> set[str]:
    """Return the Mermaid diagram declarations present in one document."""
    kinds = set(_MERMAID_FENCE_RE.findall(document))
    if "graph" in kinds:
        kinds.remove("graph")
        kinds.add("flowchart")
    if "stateDiagram-v2" in kinds:
        kinds.remove("stateDiagram-v2")
        kinds.add("stateDiagram")
    return kinds


def _registry_counts(registry: Mapping[str, Any]) -> tuple[int, int, int, int]:
    """Return recomputed issue, claim, family, and unique-semantics counts."""
    _require(registry.get("schema") == _REGISTRY_SCHEMA, "unexpected registry schema")
    issues = registry.get("issues")
    families = registry.get("detector_families")
    _require(isinstance(issues, list), "registry issues must be a list")
    _require(isinstance(families, Mapping), "registry detector_families must be an object")
    claim_count = 0
    unique_claim_semantics: set[tuple[str, str]] = set()
    for issue in issues:
        _require(isinstance(issue, Mapping), "registry issue must be an object")
        claims = issue.get("claims")
        _require(isinstance(claims, list), "registry issue claims must be a list")
        claim_count += len(claims)
        for claim in claims:
            _require(isinstance(claim, Mapping), "registry claim must be an object")
            unique_claim_semantics.add(
                (str(claim.get("detector_family")), str(claim.get("claim_id")))
            )
    return len(issues), claim_count, len(families), len(unique_claim_semantics)


def audit_issue_detection_documentation(
    repository_root: Path,
    manifest_path: Path,
) -> DocumentationAudit:
    """Validate documentation topology, diagrams, status, and registry identity."""
    root = repository_root.resolve()
    manifest = _load_object(manifest_path, "documentation manifest")
    _require(manifest.get("schema") == _MANIFEST_SCHEMA, "unexpected manifest schema")

    artifacts = manifest.get("artifacts")
    _require(isinstance(artifacts, list), "manifest artifacts must be a list")
    artifact_roles: set[str] = set()
    all_diagrams: set[str] = set()
    for artifact in artifacts:
        _require(isinstance(artifact, Mapping), "manifest artifact must be an object")
        role = artifact.get("role")
        state = artifact.get("state")
        _require(isinstance(role, str) and role in _REQUIRED_ROLES, "unknown artifact role")
        _require(role not in artifact_roles, f"duplicate artifact role: {role}")
        _require(state in _ALLOWED_ARTIFACT_STATES, f"invalid artifact state: {state}")
        artifact_roles.add(role)
        path = _resolve_declared_path(root, artifact.get("path"))
        _require(
            path.is_file(),
            f"declared documentation artifact does not exist: {path.relative_to(root)}",
        )
        try:
            document = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"unable to read documentation artifact: {path}") from exc
        present_diagrams = _diagram_kinds(document)
        missing_diagrams = _REQUIRED_DIAGRAMS.get(role, set()) - present_diagrams
        _require(
            not missing_diagrams,
            "missing required Mermaid diagram "
            f"for {role}: {','.join(sorted(missing_diagrams))}",
        )
        all_diagrams.update(present_diagrams)
    _require(
        artifact_roles == set(_REQUIRED_ROLES),
        "manifest does not declare every required artifact role",
    )

    capability_states = manifest.get("capability_states")
    _require(
        isinstance(capability_states, Mapping),
        "manifest capability_states must be an object",
    )
    _require(
        set(capability_states) == _REQUIRED_CAPABILITIES,
        "manifest capability state keys are incomplete",
    )
    _require(
        all(state in _ALLOWED_CAPABILITY_STATES for state in capability_states.values()),
        "manifest contains an invalid capability state",
    )
    if capability_states["per_issue_cause_binding"] == "implemented_on_protected_main":
        _require(
            capability_states["protected_main_operational_proof"]
            == "implemented_on_protected_main",
            "per-issue completion requires protected-main operational proof",
        )

    registry_path = _resolve_declared_path(root, manifest.get("registry_path"))
    _require(registry_path.is_file(), "declared detector registry does not exist")
    registry = _load_object(registry_path, "detector registry")
    issue_count, claim_count, family_count, unique_semantics_count = _registry_counts(
        registry
    )
    inventory = manifest.get("inventory")
    _require(isinstance(inventory, Mapping), "manifest inventory must be an object")
    _require(
        inventory.get("issue_count") == issue_count,
        "manifest issue_count does not match executable registry",
    )
    _require(
        inventory.get("claim_count") == claim_count,
        "manifest claim_count does not match executable registry",
    )
    _require(
        inventory.get("detector_family_count") == family_count,
        "manifest detector_family_count does not match executable registry",
    )
    _require(
        inventory.get("unique_claim_semantics_count") == unique_semantics_count,
        "manifest unique_claim_semantics_count does not match executable registry",
    )
    cause_bound_issue_count = inventory.get("cause_bound_issue_count")
    direct_detector_efficacy_validated_claim_count = inventory.get(
        "direct_detector_efficacy_validated_claim_count"
    )
    protected_main_operational_issue_count = inventory.get(
        "protected_main_operational_issue_count"
    )
    _require(
        isinstance(cause_bound_issue_count, int)
        and not isinstance(cause_bound_issue_count, bool)
        and 0 <= cause_bound_issue_count <= issue_count,
        "manifest cause_bound_issue_count is invalid",
    )
    _require(
        isinstance(protected_main_operational_issue_count, int)
        and not isinstance(protected_main_operational_issue_count, bool)
        and 0 <= protected_main_operational_issue_count <= cause_bound_issue_count,
        "manifest protected_main_operational_issue_count is invalid",
    )
    _require(
        isinstance(direct_detector_efficacy_validated_claim_count, int)
        and not isinstance(direct_detector_efficacy_validated_claim_count, bool)
        and 0 <= direct_detector_efficacy_validated_claim_count <= claim_count,
        "manifest direct detector efficacy count is invalid",
    )
    if capability_states["per_issue_cause_binding"] == "missing":
        _require(
            cause_bound_issue_count == 0,
            "missing per-issue cause binding requires a zero bound-issue count",
        )
    if capability_states["protected_main_operational_proof"] == "missing":
        _require(
            protected_main_operational_issue_count == 0,
            "missing protected-main proof requires a zero operational-issue count",
        )
    if capability_states["per_issue_cause_binding"] == "missing":
        _require(
            direct_detector_efficacy_validated_claim_count == 0,
            "missing cause binding requires zero validated direct-detector claims",
        )

    return DocumentationAudit(
        artifact_count=len(artifacts),
        capability_states=dict(sorted(capability_states.items())),
        cause_bound_issue_count=cause_bound_issue_count,
        claim_count=claim_count,
        detector_family_count=family_count,
        diagram_kinds=tuple(sorted(all_diagrams)),
        direct_detector_efficacy_validated_claim_count=(
            direct_detector_efficacy_validated_claim_count
        ),
        issue_count=issue_count,
        protected_main_operational_issue_count=protected_main_operational_issue_count,
        unique_claim_semantics_count=unique_semantics_count,
    )
