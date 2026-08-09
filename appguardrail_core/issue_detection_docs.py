"""Validate declared documentation topology, counts, and delivery states.

The guard resolves unique declared artifacts and local links, checks ADR
index/detail structure and required diagram declarations, binds inventory
counts to the packaged registry, and rejects inconsistent declared completion.
It does not interpret prose truth, validate remote Git ancestry, establish
standards currency, or prove detector efficacy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import unquote


_MANIFEST_SCHEMA = "appguardrail.issue-detection-documentation.v2"
_REGISTRY_SCHEMA = "appguardrail.issue-detection-registry.v1"
_EXPECTED_REPOSITORY = "ContextualWisdomLab/appguardrail"
_EXPECTED_DELIVERY_STATE = "active_pr"
_EXPECTED_VALIDATOR_SCOPE = "topology_count_declared_status_guard"
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
    "current_in_active_pr",
    "partial_in_active_pr",
}
_EXPECTED_ARTIFACT_STATES = {
    role: (
        "partial_in_active_pr"
        if role in {"incident_runbook", "operability"}
        else "current_in_active_pr"
    )
    for role in _REQUIRED_ROLES
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
    "direct_detector_efficacy",
    "family_adapter_coverage",
    "inventory_coverage",
    "per_issue_cause_binding",
    "protected_main_operational_proof",
    "source_result_instrumentation",
}
_REQUIRED_SUPPORTING_PATHS = {
    ".github/workflows/issue-detection-coverage.yml",
    ".github/workflows/issue-detection-registry-audit.yml",
    "AGENTS.md",
    "CHANGELOG.d/issue-detection-contract.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "README.md",
    "SECURITY.md",
    "docs/methodology.md",
    "docs/product/2026-07-02-2b-krw-sale-readiness-plan.md",
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
_MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)\s]+)(?:\s+[^)]*)?\)")
_HEADING_RE = re.compile(r"(?m)^#{1,6}\s+(.+?)\s*#*\s*$")
_ADR_INDEX_LINK_RE = re.compile(
    r"\[(ADR-(\d{4}))\]\((ADR-\d{4}-[^)]+\.md)\)"
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_IMPLEMENTED = "implemented_on_protected_main"


@dataclass(frozen=True)
class DocumentationAudit:
    """Validated documentation topology, counts, and declared states."""

    adr_count: int
    artifact_count: int
    capability_states: dict[str, str]
    cause_bound_issue_count: int
    claim_count: int
    detector_family_count: int
    diagram_kinds: tuple[str, ...]
    direct_detector_efficacy_validated_claim_count: int
    documentation_delivery_state: str
    issue_count: int
    local_link_count: int
    protected_main_operational_issue_count: int
    supporting_artifact_count: int
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


def _read_text(path: Path, label: str) -> str:
    """Read one UTF-8 text artifact with a bounded public error."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"unable to read {label}: {path}") from exc


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


def _heading_anchors(document: str) -> set[str]:
    """Return deterministic GitHub-style anchors for Markdown headings."""
    anchors: set[str] = set()
    occurrences: dict[str, int] = {}
    for heading in _HEADING_RE.findall(document):
        plain = re.sub(r"[\x60*_~]", "", heading).strip().lower()
        base = re.sub(r"[^\w\- ]", "", plain)
        base = re.sub(r"\s+", "-", base).strip("-")
        suffix = occurrences.get(base, 0)
        occurrences[base] = suffix + 1
        anchors.add(base if suffix == 0 else f"{base}-{suffix}")
    return anchors


def _validate_local_links(root: Path, source: Path, document: str) -> int:
    """Resolve local Markdown file/anchor links and return their count."""
    count = 0
    for raw_target in _MARKDOWN_LINK_RE.findall(document):
        target = raw_target.strip("<>")
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
            continue
        file_part, separator, anchor = target.partition("#")
        if file_part.startswith("/"):
            candidate = (root / unquote(file_part.lstrip("/"))).resolve()
        elif file_part:
            candidate = (source.parent / unquote(file_part)).resolve()
        else:
            candidate = source.resolve()
        _require(
            candidate.is_relative_to(root),
            f"local documentation link escapes repository: {source}: {target}",
        )
        _require(
            candidate.is_file(),
            f"broken local documentation link: {source.relative_to(root)}: {target}",
        )
        if separator and anchor:
            target_document = _read_text(candidate, "linked documentation artifact")
            _require(
                unquote(anchor).lower() in _heading_anchors(target_document),
                f"broken local documentation anchor: "
                f"{source.relative_to(root)}: {target}",
            )
        count += 1
    return count


def _validate_manifest_metadata(manifest: Mapping[str, Any]) -> None:
    """Validate local manifest identity fields without claiming remote ancestry."""
    _require(manifest.get("schema") == _MANIFEST_SCHEMA, "unexpected manifest schema")
    _require(
        manifest.get("repository") == _EXPECTED_REPOSITORY,
        "unexpected manifest repository",
    )
    assessment_date = manifest.get("assessment_date")
    _require(isinstance(assessment_date, str), "assessment_date must be an ISO date")
    try:
        date.fromisoformat(assessment_date)
    except ValueError as exc:
        raise ValueError("assessment_date must be an ISO date") from exc
    protected_main_sha = manifest.get("protected_main_sha")
    _require(
        isinstance(protected_main_sha, str) and bool(_SHA_RE.fullmatch(protected_main_sha)),
        "protected_main_sha must be 40 lowercase hexadecimal characters",
    )
    pull_request = manifest.get("pull_request")
    _require(
        isinstance(pull_request, int)
        and not isinstance(pull_request, bool)
        and pull_request > 0,
        "pull_request must be a positive integer",
    )
    _require(
        manifest.get("documentation_delivery_state") == _EXPECTED_DELIVERY_STATE,
        "documentation delivery state must be active_pr",
    )
    _require(
        manifest.get("validator_scope") == _EXPECTED_VALIDATOR_SCOPE,
        "unexpected documentation validator scope",
    )
    _require(
        manifest.get("manual_semantic_review_required") is True,
        "manual semantic review must remain required",
    )


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


def _validate_adr_index(root: Path, index_path: Path, index_document: str) -> int:
    """Require every status-bearing ADR detail to appear exactly once in the index."""
    matches = _ADR_INDEX_LINK_RE.findall(index_document)
    indexed_files = [filename for _adr_id, _digits, filename in matches]
    _require(bool(indexed_files), "ADR index contains no ADR detail links")
    _require(
        len(indexed_files) == len(set(indexed_files)),
        "ADR index contains a duplicate ADR detail link",
    )
    actual_files = sorted(path.name for path in index_path.parent.glob("ADR-[0-9][0-9][0-9][0-9]-*.md"))
    _require(
        sorted(indexed_files) == actual_files,
        "ADR index/detail set is incomplete or contains an orphan",
    )
    for adr_id, digits, filename in matches:
        adr_path = index_path.parent / filename
        document = _read_text(adr_path, "ADR detail")
        heading = re.search(r"(?m)^# (ADR-(\d{4})): .+$", document)
        _require(
            heading is not None and heading.group(1) == adr_id and heading.group(2) == digits,
            f"ADR heading does not match index identity: {filename}",
        )
        status_match = re.search(
            r"(?m)^Status: (Proposed|Accepted|Superseded|Rejected)$",
            document,
        )
        _require(status_match is not None, f"ADR status is missing or invalid: {filename}")
        _require(
            re.search(r"(?m)^Date: \d{4}-\d{2}-\d{2}$", document) is not None,
            f"ADR date is missing or invalid: {filename}",
        )
        _require(
            re.search(r"(?m)^Implementation: \S", document) is not None,
            f"ADR implementation status is missing: {filename}",
        )
        _require(
            f"| [{adr_id}]({filename}) | {status_match.group(1)} |" in index_document,
            f"ADR index status disagrees with detail: {filename}",
        )
    return len(matches)


def _validate_contract_tokens(documents: Mapping[str, str]) -> None:
    """Require stable requirement IDs and primary-reference identifiers."""
    for number in range(1, 10):
        _require(f"PR-{number:02d}" in documents["prd"], f"missing PRD ID: PR-{number:02d}")
    for number in range(1, 11):
        _require(f"TR-{number:02d}" in documents["trd"], f"missing TRD ID: TR-{number:02d}")
    for reference in (
        "https://doi.org/10.6028/NIST.SP.800-218",
        "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/",
        "https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28",
    ):
        _require(reference in documents["trd"], f"missing TRD primary reference: {reference}")
    _require(
        "https://csrc.nist.gov/pubs/sp/800/61/r3/final"
        in documents["incident_runbook"],
        "missing incident-response primary reference",
    )


def _validate_completion_state(
    capability: str,
    state: str,
    count: int,
    total: int,
) -> None:
    """Keep declared shipped/missing states bidirectionally aligned with counts."""
    if state == _IMPLEMENTED:
        _require(count == total, f"{capability} shipped state requires complete count")
    if count == total:
        _require(state == _IMPLEMENTED, f"{capability} complete count requires shipped state")
    if state == "missing":
        _require(count == 0, f"{capability} missing state requires zero count")


def audit_issue_detection_documentation(
    repository_root: Path,
    manifest_path: Path,
) -> DocumentationAudit:
    """Validate local topology/count/state claims without remote or semantic proof."""
    root = repository_root.resolve()
    manifest = _load_object(manifest_path, "documentation manifest")
    _validate_manifest_metadata(manifest)

    artifacts = manifest.get("artifacts")
    _require(isinstance(artifacts, list), "manifest artifacts must be a list")
    for artifact in artifacts:
        _require(isinstance(artifact, Mapping), "manifest artifact must be an object")
        path = _resolve_declared_path(root, artifact.get("path"))
        _require(
            path.is_file(),
            f"declared documentation artifact does not exist: {path.relative_to(root)}",
        )
    artifact_roles: set[str] = set()
    declared_paths: set[Path] = set()
    documents: dict[str, str] = {}
    all_diagrams: set[str] = set()
    local_link_count = 0
    for artifact in artifacts:
        _require(isinstance(artifact, Mapping), "manifest artifact must be an object")
        role = artifact.get("role")
        state = artifact.get("state")
        _require(isinstance(role, str) and role in _REQUIRED_ROLES, "unknown artifact role")
        _require(role not in artifact_roles, f"duplicate artifact role: {role}")
        _require(state in _ALLOWED_ARTIFACT_STATES, f"invalid artifact state: {state}")
        _require(
            state == _EXPECTED_ARTIFACT_STATES[role],
            f"unexpected artifact delivery state for {role}: {state}",
        )
        artifact_roles.add(role)
        path = _resolve_declared_path(root, artifact.get("path"))
        _require(path not in declared_paths, f"duplicate declared artifact path: {path.relative_to(root)}")
        declared_paths.add(path)
        _require(
            path.is_file(),
            f"declared documentation artifact does not exist: {path.relative_to(root)}",
        )
        document = _read_text(path, "documentation artifact")
        documents[role] = document
        present_diagrams = _diagram_kinds(document)
        missing_diagrams = _REQUIRED_DIAGRAMS.get(role, set()) - present_diagrams
        _require(
            not missing_diagrams,
            "missing required Mermaid diagram "
            f"for {role}: {','.join(sorted(missing_diagrams))}",
        )
        all_diagrams.update(present_diagrams)
        local_link_count += _validate_local_links(root, path, document)
    _require(
        artifact_roles == set(_REQUIRED_ROLES),
        "manifest does not declare every required artifact role",
    )

    supporting_artifacts = manifest.get("supporting_artifacts")
    _require(
        isinstance(supporting_artifacts, list),
        "manifest supporting_artifacts must be a list",
    )
    supporting_paths: set[str] = set()
    for artifact in supporting_artifacts:
        _require(isinstance(artifact, Mapping), "supporting artifact must be an object")
        state = artifact.get("state")
        _require(state in _ALLOWED_ARTIFACT_STATES, f"invalid supporting artifact state: {state}")
        path = _resolve_declared_path(root, artifact.get("path"))
        relative = str(path.relative_to(root))
        _require(relative not in supporting_paths, f"duplicate supporting artifact path: {relative}")
        _require(path not in declared_paths, f"artifact path is declared twice: {relative}")
        supporting_paths.add(relative)
        declared_paths.add(path)
        _require(path.is_file(), f"supporting artifact does not exist: {relative}")
        document = _read_text(path, "supporting documentation artifact")
        local_link_count += _validate_local_links(root, path, document)
    _require(
        supporting_paths == _REQUIRED_SUPPORTING_PATHS,
        "manifest supporting artifact set is incomplete",
    )

    adr_index_path = _resolve_declared_path(
        root,
        next(artifact["path"] for artifact in artifacts if artifact["role"] == "adr_index"),
    )
    adr_count = _validate_adr_index(root, adr_index_path, documents["adr_index"])
    _validate_contract_tokens(documents)

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

    registry_path = _resolve_declared_path(root, manifest.get("registry_path"))
    _require(registry_path.is_file(), "declared detector registry does not exist")
    registry = _load_object(registry_path, "detector registry")
    issue_count, claim_count, family_count, unique_semantics_count = _registry_counts(registry)
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
    _validate_completion_state(
        "per-issue cause binding",
        str(capability_states["per_issue_cause_binding"]),
        cause_bound_issue_count,
        issue_count,
    )
    _validate_completion_state(
        "direct detector efficacy",
        str(capability_states["direct_detector_efficacy"]),
        direct_detector_efficacy_validated_claim_count,
        claim_count,
    )
    _validate_completion_state(
        "protected-main operational proof",
        str(capability_states["protected_main_operational_proof"]),
        protected_main_operational_issue_count,
        issue_count,
    )
    if capability_states["direct_detector_efficacy"] == _IMPLEMENTED:
        _require(
            capability_states["per_issue_cause_binding"] == _IMPLEMENTED,
            "direct detector efficacy requires shipped per-issue cause binding",
        )
    if direct_detector_efficacy_validated_claim_count > 0:
        has_cause_binding = cause_bound_issue_count > 0
        cause_state_available = capability_states["per_issue_cause_binding"] != "missing"
        _require(
            has_cause_binding and cause_state_available,
            "validated direct efficacy requires non-missing cause binding",
        )

    return DocumentationAudit(
        adr_count=adr_count,
        artifact_count=len(artifacts),
        capability_states=dict(sorted(capability_states.items())),
        cause_bound_issue_count=cause_bound_issue_count,
        claim_count=claim_count,
        detector_family_count=family_count,
        diagram_kinds=tuple(sorted(all_diagrams)),
        direct_detector_efficacy_validated_claim_count=(
            direct_detector_efficacy_validated_claim_count
        ),
        documentation_delivery_state=str(manifest["documentation_delivery_state"]),
        issue_count=issue_count,
        local_link_count=local_link_count,
        protected_main_operational_issue_count=protected_main_operational_issue_count,
        supporting_artifact_count=len(supporting_artifacts),
        unique_claim_semantics_count=unique_semantics_count,
    )
