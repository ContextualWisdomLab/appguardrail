"""Classify issue-derived workflow evidence without publishing raw job logs.

Every AppGuardrail repository issue is a retained detection requirement.  This
module supplies the shared result model, cause classifier, and registry audit
used to prove that the requirement remains addressable.  Authorized logs may
be inspected in memory, but only bounded detector identifiers and hashes of
non-secret classification metadata leave the classifier.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, TextIO


_REGISTRY_PATH = Path(__file__).with_name("issue_detection_registry.json")
_RESULT_ATTESTATION_KEY_ENV = "APPGUARDRAIL_WORKFLOW_RESULT_HMAC_KEY"
_FAMILY_BY_JOB = {
    "opencode-review": "opencode-review-gate-diagnostics",
    "strix": "strix-security-gate-diagnostics",
    "publish-manual-pr-evidence-status": "pr-evidence-publication-health",
    "coverage-evidence": "coverage-evidence-control",
    "trivy-fs": "trivy-filesystem-gate-diagnostics",
    "validate-pr-metadata": "pull-request-metadata-policy",
    "noema-review": "noema-review-gate-diagnostics",
    "codeql analysis": "codeql-analysis-gate-diagnostics",
    "codeql merge preview (python)": "codeql-analysis-gate-diagnostics",
    "appguardrail-scan": "native-appguardrail-gate-diagnostics",
}
_PRODUCERS_BY_FAMILY = {
    "codeql-analysis-gate-diagnostics": {"codeql"},
    "coverage-evidence-control": {"coverage-evidence"},
    "native-appguardrail-gate-diagnostics": {"appguardrail"},
    "noema-review-gate-diagnostics": {"noema"},
    "opencode-review-gate-diagnostics": {"opencode"},
    "pr-evidence-publication-health": {"pr-evidence-publisher"},
    "pull-request-metadata-policy": {"pr-metadata-validator"},
    "strix-security-gate-diagnostics": {"strix"},
    "trivy-filesystem-gate-diagnostics": {"trivy"},
}
_OPERATIONAL_CAUSES_BY_FAMILY = {
    "codeql-analysis-gate-diagnostics": {
        "build_failure",
        "configuration",
        "database_failure",
        "superseded_cancellation",
        "upload_failure",
    },
    "native-appguardrail-gate-diagnostics": {
        "rules_configuration",
        "scanner_execution",
        "workflow_cancellation",
    },
    "noema-review-gate-diagnostics": {
        "dispatch_rejected",
        "provider_auth",
        "provider_rate_limit",
        "publication_failure",
        "reviewer_execution",
        "superseded_cancellation",
    },
    "opencode-review-gate-diagnostics": {
        "dispatch_rejected",
        "github_permission_auth",
        "manual_cancellation",
        "provider_auth",
        "provider_rate_limit",
        "publication_failure",
        "reviewer_execution",
        "superseded_cancellation",
    },
    "strix-security-gate-diagnostics": {
        "provider_auth",
        "provider_rate_limit",
        "result_mapping",
        "scanner_execution",
        "scanner_setup",
        "workflow_cancellation",
    },
    "trivy-filesystem-gate-diagnostics": {
        "database_update",
        "provider_rate_limit",
        "scan_execution",
        "scanner_setup",
        "superseded_cancellation",
    },
}
_RATE_LIMIT_RE = re.compile(
    r"ratelimiterror|error code:\s*429|http\s*429|too many requests|"
    r"resource_exhausted|insufficient_quota",
    re.IGNORECASE,
)
_PUBLICATION_DENIED_RE = re.compile(
    r"resource not accessible by integration\s*\(http 403\)|"
    r"(?:publish|publication|status).{0,120}(?:http\s*)?403|"
    r"(?:http\s*)?403.{0,120}(?:publish|publication|status)",
    re.IGNORECASE | re.DOTALL,
)
_REQUEST_CHANGES_RE = re.compile(r"(?:^|\n)request_changes\s*:", re.IGNORECASE)
_POSITIVE_VULNERABILITY_RE = re.compile(
    r"\bvulnerabilities\s+([1-9][0-9]*)\b", re.IGNORECASE
)
_ZERO_VULNERABILITY_RE = re.compile(r"\bvulnerabilities\s+0\b", re.IGNORECASE)
_DISPATCH_REJECTION_RE = re.compile(
    r"repository_dispatch (?:authorization|metadata) (?:rejected|does not match)",
    re.IGNORECASE,
)
_COVERAGE_BLOCK_RE = re.compile(
    r"coverage.{0,120}(?:below|failed|missing|malformed|threshold)",
    re.IGNORECASE | re.DOTALL,
)
_TIMEOUT_RE = re.compile(r"\btimed?\s*out\b|timeouterror", re.IGNORECASE)
_SHA_RE = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_IMPLEMENTATION_REF_RE = re.compile(
    r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.py:[A-Za-z_][A-Za-z0-9_]*"
)
_FORBIDDEN_REGISTRY_FIELDS = {
    "excluded",
    "exclusion",
    "not_applicable",
    "suppressed",
    "waiver",
    "waived",
}
_REQUIRED_FAMILY_FIELDS = {
    "adapter_id",
    "adapter_ref",
    "cluster_id",
    "condition",
    "evidence_schema",
    "evidence_fields",
    "evidence_sources",
    "expected_structured_outcome",
    "fixtures",
    "implementation_refs",
    "no_exclusions",
    "obligations",
    "outcome_states",
    "required_evidence_fields",
}


@dataclass(frozen=True)
class WorkflowEvidence:
    """Evidence for one security workflow job and an optional signed result."""

    workflow_name: str
    job_name: str
    conclusion: str
    log_text: str = ""
    run_id: str = ""
    head_sha: str = ""
    structured_result: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class WorkflowResultVerifier:
    """Trusted capability for authenticating source-produced result envelopes."""

    key: bytes

    def __post_init__(self) -> None:
        """Reject weak or caller-mistyped shared attestation keys."""
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("workflow result attestation key must contain 32 bytes")

    def __repr__(self) -> str:
        """Keep the shared attestation key out of logs and tracebacks."""
        return "WorkflowResultVerifier(key=<redacted>)"

    @classmethod
    def from_base64(cls, encoded_key: str) -> WorkflowResultVerifier:
        """Decode one externally provisioned base64 attestation key."""
        try:
            key = base64.b64decode(encoded_key, validate=True)
        except (TypeError, ValueError, binascii.Error) as error:
            raise ValueError("invalid base64 workflow attestation key") from error
        return cls(key)

    def verify(self, envelope: Mapping[str, Any]) -> bool:
        """Authenticate bounded envelope metadata with constant-time HMAC compare."""
        attestation = envelope.get("attestation")
        if not isinstance(attestation, str) or not _DIGEST_RE.fullmatch(attestation):
            return False
        message = _workflow_result_attestation_message(envelope)
        if message is None:
            return False
        expected = hmac.new(self.key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, attestation.casefold())


@dataclass(frozen=True)
class DetectionResult:
    """One secret-safe cause detected from a workflow issue's evidence."""

    detector_id: str
    detector_family: str
    status: str
    cause_class: str
    deploy_blocking: bool
    gate_satisfied: bool
    confirmed_security_finding: bool | None
    confidence: str
    evidence_hash: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-ready result that contains no raw source evidence."""
        return {
            "cause_class": self.cause_class,
            "confidence": self.confidence,
            "confirmed_security_finding": self.confirmed_security_finding,
            "deploy_blocking": self.deploy_blocking,
            "detector_family": self.detector_family,
            "detector_id": self.detector_id,
            "evidence_hash": self.evidence_hash,
            "gate_satisfied": self.gate_satisfied,
            "status": self.status,
        }


@dataclass(frozen=True)
class IssueDetectionClaim:
    """One independently testable claim retained from a repository issue."""

    claim_id: str
    detector_family: str


@dataclass(frozen=True)
class IssueDetectionTarget:
    """Registry binding from one GitHub issue to one or more detector claims."""

    issue_number: int
    claims: tuple[IssueDetectionClaim, ...]
    requirement_sha256: str
    issue_updated_at: str
    retained_detection_requirement: bool

    @property
    def detector_family(self) -> str:
        """Return the primary family for compatibility with cluster summaries."""
        return self.claims[0].detector_family


@dataclass(frozen=True)
class IssueDetectionRegistry:
    """Immutable snapshot of all retained issue-derived requirements."""

    schema: str
    repository: str
    inventory_as_of: str
    issue_count: int
    detector_families: Mapping[str, Mapping[str, Any]]
    issues: tuple[IssueDetectionTarget, ...]


@dataclass(frozen=True)
class IssueCoverageAudit:
    """Difference between live GitHub issues and the committed registry."""

    unmapped_issue_numbers: tuple[int, ...]
    registry_only_issue_numbers: tuple[int, ...]
    changed_issue_numbers: tuple[int, ...] = ()
    incomplete_issue_numbers: tuple[int, ...] = ()

    @property
    def complete(self) -> bool:
        """Return whether live and registered issue identities are identical."""
        return not any(
            (
                self.unmapped_issue_numbers,
                self.registry_only_issue_numbers,
                self.changed_issue_numbers,
                self.incomplete_issue_numbers,
            )
        )


@dataclass(frozen=True)
class FamilyAssessment:
    """Positive, negative, or unknown outcome from an executable family adapter."""

    detector_family: str
    status: str
    signal: str
    gate_satisfied: bool


def _family_assessment(
    detector_family: str,
    status: str,
    signal: str,
) -> FamilyAssessment:
    """Build one family assessment with fail-closed gate semantics."""
    return FamilyAssessment(
        detector_family=detector_family,
        status=status,
        signal=signal,
        gate_satisfied=status == "clean",
    )


def _schema_matches(
    evidence: Mapping[str, Any], contract: Mapping[str, Any]
) -> bool:
    """Return whether raw evidence declares the reviewed family schema."""
    return (
        isinstance(evidence, Mapping)
        and evidence.get("schema") == contract["evidence_schema"]
    )


def _is_integer(value: Any) -> bool:
    """Return whether a JSON value is an integer rather than a Boolean."""
    return isinstance(value, int) and not isinstance(value, bool)


def _text_or_empty(value: Any) -> str:
    """Return trusted text values without invoking attacker-controlled coercion."""
    return value if isinstance(value, str) else ""


def _is_finite_number(value: Any) -> bool:
    """Return whether a JSON value is a finite number rather than a Boolean."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _canonical_json_bytes(value: Any) -> bytes | None:
    """Encode canonical UTF-8 JSON, rejecting invalid scalar values safely."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        return None


def _evidence_shape_error(
    evidence: Mapping[str, Any], contract: Mapping[str, Any]
) -> str:
    """Reject evidence fields that the executable contract cannot interpret."""
    allowed = contract.get("evidence_fields")
    required = contract.get("required_evidence_fields")
    if not isinstance(allowed, list) or not isinstance(required, list):
        return "invalid_evidence_contract"
    try:
        keys = tuple(evidence.keys())
        if not all(isinstance(key, str) for key in keys):
            return "invalid_evidence_field"
        if any(key not in allowed for key in keys):
            return "unsupported_evidence_field"
        if any(key not in evidence for key in required):
            return "missing_required_evidence_field"
    except (RecursionError, RuntimeError, TypeError, UnicodeError, ValueError):
        return "invalid_evidence_field"
    return ""


def _product_control_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Evaluate the four raw product-security controls retained by issue 132."""
    boolean_fields = (
        "secret_output_redacted",
        "uses_pull_request_target",
        "fork_code_executed",
        "privileged_secret_access",
        "dependencies_hashed",
        "sbom_present",
        "artifact_attested",
        "path_contained",
        "symlink_safe",
        "subprocess_argv_only",
    )
    if not _schema_matches(evidence, contract) or not all(
        isinstance(evidence.get(field), bool) for field in boolean_fields
    ):
        return _family_assessment(family, "unknown", "incomplete_product_evidence")
    controls = {
        "secret-output-redaction": evidence["secret_output_redacted"],
        "privileged-review-workflow": not (
            evidence["uses_pull_request_target"]
            and evidence["fork_code_executed"]
            and evidence["privileged_secret_access"]
        ),
        "release-integrity": (
            evidence["dependencies_hashed"]
            and evidence["sbom_present"]
            and evidence["artifact_attested"]
        ),
        "defensive-path-and-process-controls": (
            evidence["path_contained"]
            and evidence["symlink_safe"]
            and evidence["subprocess_argv_only"]
        ),
    }
    if claim_id is not None and claim_id not in controls:
        return _family_assessment(family, "unknown", "unregistered_product_claim")
    observed = controls if claim_id is None else {claim_id: controls[claim_id]}
    violated = next((name for name, safe in observed.items() if not safe), None)
    if violated is not None:
        return _family_assessment(family, "detected", violated)
    return _family_assessment(
        family,
        "clean",
        claim_id or "product_security_controls_verified",
    )


def _openssf_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Classify official OpenSSF project evidence without inferring registration."""
    del claim_id
    response = (
        evidence.get("api_response")
        if _schema_matches(evidence, contract)
        else None
    )
    if not isinstance(response, Mapping) or not isinstance(response.get("status"), str):
        return _family_assessment(family, "unknown", "missing_official_response")
    status = str(response.get("status", ""))
    if status in {"in_progress", "legacy", "unregistered"}:
        return _family_assessment(family, "detected", status)
    if status in {"passing", "silver", "gold"}:
        return _family_assessment(family, "clean", status)
    return _family_assessment(family, "unknown", status or "malformed_response")


def _code_scanning_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Detect exact base-to-head Code Scanning analysis identity drift."""
    del claim_id
    valid = _schema_matches(evidence, contract) and evidence.get("complete") is True
    base = evidence.get("base_analysis_keys")
    head = evidence.get("head_analysis_keys")
    collection_fields = ("api_success", "pagination_complete", "permission_complete")
    if not valid or not isinstance(base, list) or not isinstance(head, list):
        return _family_assessment(family, "unknown", "incomplete_analysis_evidence")
    if not all(isinstance(item, str) for item in base + head) or not all(
        isinstance(evidence.get(field), bool) for field in collection_fields
    ):
        return _family_assessment(family, "unknown", "invalid_analysis_evidence")
    if not all(evidence[field] for field in collection_fields):
        return _family_assessment(family, "unknown", "analysis_collection_failure")
    missing = sorted(set(map(str, base)) - set(map(str, head)))
    if missing:
        return _family_assessment(family, "detected", "missing:" + ",".join(missing))
    return _family_assessment(family, "clean", "analysis_identity_parity")


def _retention_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Detect over-retention or an invalid tenant audit chain."""
    del claim_id
    valid = _schema_matches(evidence, contract) and evidence.get("complete") is True
    policy_days = evidence.get("policy_days")
    observed_age_days = evidence.get("observed_age_days")
    boolean_fields = (
        "policy_present",
        "cross_tenant_isolation",
        "purge_idempotent",
        "purge_atomic",
        "legal_hold_respected",
        "audit_chain_valid",
        "secret_safe_output",
    )
    if (
        not valid
        or not _is_integer(policy_days)
        or not _is_integer(observed_age_days)
        or policy_days < 0
        or observed_age_days < 0
        or not all(isinstance(evidence.get(field), bool) for field in boolean_fields)
    ):
        return _family_assessment(family, "unknown", "incomplete_retention_evidence")
    compliant = observed_age_days <= policy_days and all(
        evidence[field] for field in boolean_fields
    )
    if not compliant:
        return _family_assessment(family, "detected", "retention_or_audit_violation")
    return _family_assessment(family, "clean", "retention_and_audit_compliant")


def _scheduled_governance_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Detect scheduled-agent trust, provider, timeout, or concurrency drift."""
    del claim_id
    required = (
        "legacy_jules_absent",
        "provider_key_name",
        "provider_mapping_valid",
        "actions_pinned",
        "event_trust_safe",
        "permissions_least_privilege",
        "selector_valid",
        "review_credentials_isolated",
        "timeout_minutes",
        "cancel_in_progress",
    )
    if not _schema_matches(evidence, contract) or evidence.get("complete") is not True:
        return _family_assessment(family, "unknown", "incomplete_governance_evidence")
    if not all(key in evidence for key in required):
        return _family_assessment(family, "unknown", "missing_governance_field")
    boolean_fields = tuple(
        field
        for field in required
        if field not in {"provider_key_name", "timeout_minutes"}
    )
    if not isinstance(evidence["provider_key_name"], str) or not _is_integer(
        evidence["timeout_minutes"]
    ) or not all(isinstance(evidence[field], bool) for field in boolean_fields):
        return _family_assessment(family, "unknown", "invalid_governance_field")
    compliant = (
        evidence["provider_key_name"] == "NVIDIA_NIM_API_KEY"
        and 120 <= evidence["timeout_minutes"] <= 180
        and evidence["cancel_in_progress"] is False
        and all(
            evidence[field]
            for field in boolean_fields
            if field != "cancel_in_progress"
        )
    )
    return _family_assessment(
        family,
        "clean" if compliant else "detected",
        "scheduled_agent_compliant" if compliant else "scheduled_agent_drift",
    )


def _egress_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Detect unsafe authenticated HTTPS resolution or redirect behavior."""
    del claim_id
    fields = (
        "scheme",
        "dns_resolution_pinned",
        "all_resolved_ips_public",
        "mixed_address_set",
        "peer_ip_matches",
        "tls_identity_matches",
        "redirect_target_safe",
        "authorization_retained_cross_origin",
        "proxy_authorization_retained_cross_origin",
    )
    if not _schema_matches(evidence, contract) or evidence.get("complete") is not True:
        return _family_assessment(family, "unknown", "incomplete_egress_evidence")
    if not all(key in evidence for key in fields):
        return _family_assessment(family, "unknown", "missing_egress_field")
    if (
        not isinstance(evidence["scheme"], str)
        or not all(isinstance(evidence[key], bool) for key in fields[1:])
    ):
        return _family_assessment(family, "unknown", "invalid_egress_field")
    safe = (
        evidence["scheme"] == "https"
        and evidence["dns_resolution_pinned"] is True
        and evidence["all_resolved_ips_public"] is True
        and evidence["mixed_address_set"] is False
        and evidence["peer_ip_matches"] is True
        and evidence["tls_identity_matches"] is True
        and evidence["redirect_target_safe"] is True
        and evidence["authorization_retained_cross_origin"] is False
        and evidence["proxy_authorization_retained_cross_origin"] is False
    )
    return _family_assessment(
        family,
        "clean" if safe else "detected",
        "authenticated_egress_safe" if safe else "authenticated_egress_unsafe",
    )


def _scanner_path_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Detect path-context drift, unsafe symlinks, or scan-budget regressions."""
    del claim_id
    fields = (
        "scan_root",
        "reported_path",
        "elapsed_ms",
        "budget_ms",
        "normalization_count",
        "string_subclasses_supported",
        "path_values_supported",
        "dotfiles_included",
        "separators_normalized",
        "symlink_safe",
        "single_file_supported",
        "comment_auth_deferred",
        "benchmark_valid",
    )
    if not _schema_matches(evidence, contract) or evidence.get("complete") is not True:
        return _family_assessment(family, "unknown", "incomplete_scanner_evidence")
    if not all(key in evidence for key in fields):
        return _family_assessment(family, "unknown", "missing_scanner_field")
    if (
        not isinstance(evidence["scan_root"], str)
        or not evidence["scan_root"]
        or not isinstance(evidence["reported_path"], str)
        or not evidence["reported_path"]
        or not _is_integer(evidence["elapsed_ms"])
        or not _is_integer(evidence["budget_ms"])
        or not _is_integer(evidence["normalization_count"])
        or evidence["elapsed_ms"] < 0
        or evidence["budget_ms"] < 0
        or evidence["normalization_count"] < 0
        or not all(isinstance(evidence[field], bool) for field in fields[5:])
    ):
        return _family_assessment(family, "unknown", "invalid_scanner_field")
    try:
        root = Path(evidence["scan_root"]).resolve(strict=False)
        reported = Path(evidence["reported_path"]).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return _family_assessment(family, "unknown", "invalid_scanner_path")
    compliant = (
        reported.is_relative_to(root)
        and evidence["elapsed_ms"] <= evidence["budget_ms"]
        and evidence["normalization_count"] == 1
        and all(evidence[field] for field in fields[5:])
    )
    return _family_assessment(
        family,
        "clean" if compliant else "detected",
        "scanner_contract_compliant" if compliant else "scanner_contract_violation",
    )


def _builder_runtime_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Detect unsafe builder timeout, cancellation, or credential lifetime."""
    del claim_id
    fields = (
        "timeout_minutes",
        "minimum_minutes",
        "maximum_minutes",
        "cancel_in_progress",
        "credential_lifetime_minutes",
        "cadence_preserved",
        "pr_first_selection",
        "single_flight_serialized",
        "default_branch_trust_safe",
        "action_pinned",
        "provider_mapping_valid",
    )
    if not _schema_matches(evidence, contract) or evidence.get("complete") is not True:
        return _family_assessment(family, "unknown", "incomplete_runtime_evidence")
    if not all(key in evidence for key in fields):
        return _family_assessment(family, "unknown", "missing_runtime_field")
    numeric_fields = (
        "timeout_minutes",
        "minimum_minutes",
        "maximum_minutes",
        "credential_lifetime_minutes",
    )
    if (
        not all(_is_integer(evidence[key]) for key in numeric_fields)
        or not all(evidence[key] >= 0 for key in numeric_fields)
        or not all(
            isinstance(evidence[field], bool)
            for field in (
                "cancel_in_progress",
                "cadence_preserved",
                "pr_first_selection",
                "single_flight_serialized",
                "default_branch_trust_safe",
                "action_pinned",
                "provider_mapping_valid",
            )
        )
    ):
        return _family_assessment(family, "unknown", "invalid_runtime_field")
    timeout = evidence["timeout_minutes"]
    compliant = (
        evidence["minimum_minutes"] <= timeout <= evidence["maximum_minutes"]
        and evidence["cancel_in_progress"] is False
        and evidence["credential_lifetime_minutes"] >= timeout
        and evidence["cadence_preserved"] is True
        and evidence["pr_first_selection"] is True
        and evidence["single_flight_serialized"] is True
        and evidence["default_branch_trust_safe"] is True
        and evidence["action_pinned"] is True
        and evidence["provider_mapping_valid"] is True
    )
    return _family_assessment(
        family,
        "clean" if compliant else "detected",
        "builder_runtime_compliant" if compliant else "builder_runtime_violation",
    )


def _workflow_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
    workflow_result_verifier: WorkflowResultVerifier | None = None,
) -> FamilyAssessment:
    """Detect a concrete workflow cause from raw metadata and a bound result."""
    del claim_id
    if not _schema_matches(evidence, contract):
        return _family_assessment(family, "unknown", "wrong_workflow_schema")
    required = ("workflow_name", "job_name", "conclusion")
    if not all(
        isinstance(evidence.get(key), str) and bool(evidence.get(key))
        for key in required
    ):
        return _family_assessment(family, "unknown", "missing_workflow_identity")
    optional_text = ("log_text", "run_id", "head_sha")
    if any(
        key in evidence and not isinstance(evidence[key], str)
        for key in optional_text
    ) or (
        evidence.get("structured_result") is not None
        and not isinstance(evidence.get("structured_result"), Mapping)
    ):
        return _family_assessment(family, "unknown", "invalid_workflow_evidence")
    if detector_family_for_job(
        evidence["job_name"], evidence["workflow_name"]
    ) != family:
        return _family_assessment(family, "unknown", "workflow_family_mismatch")
    results = detect_workflow_causes(
        WorkflowEvidence(
            workflow_name=evidence["workflow_name"],
            job_name=evidence["job_name"],
            conclusion=evidence["conclusion"],
            log_text=evidence.get("log_text", ""),
            run_id=evidence.get("run_id", ""),
            head_sha=evidence.get("head_sha", ""),
            structured_result=evidence.get("structured_result"),
        ),
        workflow_result_verifier=workflow_result_verifier,
    )
    if any(result.confirmed_security_finding is True for result in results):
        return _family_assessment(family, "detected", "confirmed_finding")
    if results and all(result.gate_satisfied for result in results):
        return _family_assessment(family, "clean", "verified_clean")
    if any(result.status != "inconclusive" for result in results):
        return _family_assessment(family, "detected", results[0].cause_class)
    return _family_assessment(family, "unknown", results[0].cause_class)


def _publication_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Detect evidence-publication failure without erasing the upstream result."""
    del claim_id
    if not _schema_matches(evidence, contract) or evidence.get("complete") is not True:
        return _family_assessment(family, "unknown", "incomplete_publication_evidence")
    status_code = evidence.get("status_code")
    preserved = evidence.get("upstream_result_preserved")
    if not _is_integer(status_code) or not isinstance(preserved, bool):
        return _family_assessment(family, "unknown", "invalid_publication_evidence")
    published = 200 <= status_code < 300 and preserved
    return _family_assessment(
        family,
        "clean" if published else "detected",
        "published" if published else "reporting_failed",
    )


def _coverage_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Detect malformed or below-threshold coverage evidence."""
    del claim_id
    if not _schema_matches(evidence, contract) or evidence.get("complete") is not True:
        return _family_assessment(family, "unknown", "incomplete_coverage_evidence")
    measured = evidence.get("measured_percent")
    required = evidence.get("required_percent")
    boolean_fields = (
        "artifact_present",
        "artifact_valid",
        "artifact_fresh",
        "artifact_published",
        "infrastructure_available",
    )
    if (
        not _is_finite_number(measured)
        or not _is_finite_number(required)
        or not 0 <= measured <= 100
        or not 0 <= required <= 100
    ):
        return _family_assessment(family, "unknown", "invalid_coverage_measurement")
    if not all(isinstance(evidence.get(field), bool) for field in boolean_fields):
        return _family_assessment(family, "unknown", "invalid_coverage_artifact")
    if evidence["infrastructure_available"] is False:
        return _family_assessment(family, "unknown", "coverage_infrastructure_failure")
    accepted = all(evidence[field] for field in boolean_fields) and measured >= required
    return _family_assessment(
        family,
        "clean" if accepted else "detected",
        "coverage_accepted" if accepted else "coverage_rejected",
    )


def _pr_metadata_adapter(
    family: str,
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    claim_id: str | None,
) -> FamilyAssessment:
    """Detect invalid required pull-request dispatch metadata."""
    del claim_id
    fields = (
        "actor_matches_scheduler",
        "sender_matches_scheduler",
        "required_fields_present",
        "validator_executed",
        "publication_succeeded",
    )
    if not _schema_matches(evidence, contract) or evidence.get("complete") is not True:
        return _family_assessment(family, "unknown", "incomplete_pr_metadata")
    if not all(isinstance(evidence.get(key), bool) for key in fields):
        return _family_assessment(family, "unknown", "invalid_pr_metadata")
    if evidence["validator_executed"] is False:
        return _family_assessment(family, "unknown", "metadata_validator_failure")
    if evidence["publication_succeeded"] is False:
        return _family_assessment(family, "unknown", "metadata_publication_failure")
    compliant = all(evidence[key] for key in fields)
    return _family_assessment(
        family,
        "clean" if compliant else "detected",
        "pr_metadata_compliant" if compliant else "pr_metadata_rejected",
    )


_FAMILY_ADAPTERS = {
    "authenticated-egress-destination-and-redirect-safety": _egress_adapter,
    "codeql-analysis-gate-diagnostics": _workflow_adapter,
    "coverage-evidence-control": _coverage_adapter,
    "github-code-scanning-analysis-drift": _code_scanning_adapter,
    "native-appguardrail-gate-diagnostics": _workflow_adapter,
    "noema-review-gate-diagnostics": _workflow_adapter,
    "opencode-review-gate-diagnostics": _workflow_adapter,
    "openssf-best-practices-evidence": _openssf_adapter,
    "pr-evidence-publication-health": _publication_adapter,
    "product-security-audit-controls": _product_control_adapter,
    "pull-request-metadata-policy": _pr_metadata_adapter,
    "scanner-path-contract-and-performance": _scanner_path_adapter,
    "scheduled-agent-workflow-governance": _scheduled_governance_adapter,
    "scheduled-builder-runtime-contract": _builder_runtime_adapter,
    "strix-security-gate-diagnostics": _workflow_adapter,
    "tenant-retention-and-audit-posture": _retention_adapter,
    "trivy-filesystem-gate-diagnostics": _workflow_adapter,
}


def registered_detector_families() -> tuple[str, ...]:
    """Return every family with a closed, callable evidence adapter."""
    return tuple(_FAMILY_ADAPTERS)


def evaluate_detector_family(
    detector_family: str,
    evidence: Any,
    *,
    registry: IssueDetectionRegistry | None = None,
    workflow_result_verifier: WorkflowResultVerifier | None = None,
) -> FamilyAssessment:
    """Evaluate structured evidence through one registered family adapter."""
    adapter = _FAMILY_ADAPTERS.get(detector_family)
    if adapter is None:
        raise ValueError(f"unregistered detector family: {detector_family}")
    active_registry = load_issue_detection_registry() if registry is None else registry
    contract = active_registry.detector_families[detector_family]
    if not isinstance(evidence, Mapping):
        return _family_assessment(
            detector_family,
            "unknown",
            "invalid_evidence_object",
        )
    shape_error = _evidence_shape_error(evidence, contract)
    if shape_error:
        return _family_assessment(detector_family, "unknown", shape_error)
    if adapter is _workflow_adapter:
        return adapter(
            detector_family,
            evidence,
            contract,
            None,
            workflow_result_verifier,
        )
    return adapter(detector_family, evidence, contract, None)


def _replace_claim_token(value: Any, claim_id: str) -> Any:
    """Materialize one inherited family fixture for a specific issue claim."""
    if isinstance(value, list):
        return [_replace_claim_token(item, claim_id) for item in value]
    if isinstance(value, Mapping):
        return {
            key: _replace_claim_token(nested, claim_id)
            for key, nested in value.items()
        }
    return claim_id if value == "$claim_id" else value


def materialize_issue_claim_fixture(
    issue_number: int,
    claim_id: str,
    fixture_name: str,
    *,
    registry: IssueDetectionRegistry | None = None,
) -> Mapping[str, Any]:
    """Materialize a committed test fixture for one registered issue claim."""
    active_registry = load_issue_detection_registry() if registry is None else registry
    target = next(
        (item for item in active_registry.issues if item.issue_number == issue_number),
        None,
    )
    if target is None:
        raise ValueError(f"unregistered issue number: {issue_number}")
    claim = next((item for item in target.claims if item.claim_id == claim_id), None)
    if claim is None:
        raise ValueError(f"unregistered issue claim: {issue_number}#{claim_id}")
    fixtures = active_registry.detector_families[claim.detector_family]["fixtures"]
    if fixture_name not in {"positive", "negative", "unknown"}:
        raise ValueError(f"unregistered issue fixture: {fixture_name}")
    materialized = _replace_claim_token(fixtures[fixture_name], claim_id)
    return materialized


def evaluate_issue_claim(
    issue_number: int,
    claim_id: str,
    evidence: Any,
    *,
    registry: IssueDetectionRegistry | None = None,
    workflow_result_verifier: WorkflowResultVerifier | None = None,
) -> FamilyAssessment:
    """Evaluate raw evidence against one exact historical issue claim."""
    active_registry = load_issue_detection_registry() if registry is None else registry
    target = next(
        (item for item in active_registry.issues if item.issue_number == issue_number),
        None,
    )
    if target is None:
        raise ValueError(f"unregistered issue number: {issue_number}")
    claim = next((item for item in target.claims if item.claim_id == claim_id), None)
    if claim is None:
        raise ValueError(f"unregistered issue claim: {issue_number}#{claim_id}")
    adapter = _FAMILY_ADAPTERS[claim.detector_family]
    contract = active_registry.detector_families[claim.detector_family]
    if not isinstance(evidence, Mapping):
        return _family_assessment(
            claim.detector_family,
            "unknown",
            "invalid_evidence_object",
        )
    shape_error = _evidence_shape_error(evidence, contract)
    if shape_error:
        return _family_assessment(claim.detector_family, "unknown", shape_error)
    if adapter is _workflow_adapter:
        return adapter(
            claim.detector_family,
            evidence,
            contract,
            claim_id,
            workflow_result_verifier,
        )
    return adapter(claim.detector_family, evidence, contract, claim_id)


def detector_family_for_job(job_name: str, workflow_name: str = "") -> str:
    """Return the detector family responsible for one observed workflow job."""
    del workflow_name
    normalized_job = _text_or_empty(job_name).strip().casefold()
    if normalized_job in _FAMILY_BY_JOB:
        return _FAMILY_BY_JOB[normalized_job]
    return "unregistered"


def _evidence_hash(evidence: WorkflowEvidence, detector_id: str) -> str:
    """Hash only non-secret classification identity, never the inspected log."""
    structured_result = (
        evidence.structured_result
        if isinstance(evidence.structured_result, Mapping)
        else {}
    )
    payload = json.dumps(
        {
            "conclusion": _text_or_empty(evidence.conclusion).strip().casefold(),
            "detector_id": detector_id,
            "head_sha": _text_or_empty(evidence.head_sha).strip().casefold(),
            "job": _text_or_empty(evidence.job_name).strip().casefold(),
            "payload_sha256": _text_or_empty(
                structured_result.get("payload_sha256", "")
            )
            .strip()
            .casefold(),
            "run_id": _text_or_empty(evidence.run_id).strip(),
            "workflow": _text_or_empty(evidence.workflow_name).strip().casefold(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _result(
    evidence: WorkflowEvidence,
    *,
    detector_id: str,
    status: str,
    cause_class: str,
    deploy_blocking: bool,
    gate_satisfied: bool,
    confirmed_security_finding: bool | None,
    confidence: str = "authorized_log",
) -> DetectionResult:
    """Build one bounded, deterministic workflow detection result."""
    return DetectionResult(
        detector_id=detector_id,
        detector_family=detector_family_for_job(
            evidence.job_name, evidence.workflow_name
        ),
        status=status,
        cause_class=cause_class,
        deploy_blocking=deploy_blocking,
        gate_satisfied=gate_satisfied,
        confirmed_security_finding=confirmed_security_finding,
        confidence=confidence,
        evidence_hash=_evidence_hash(evidence, detector_id),
    )


def _workflow_result_attestation_message(
    envelope: Mapping[str, Any],
) -> bytes | None:
    """Canonicalize the bounded result metadata authenticated by a producer."""
    fields = (
        "schema",
        "producer",
        "run_id",
        "head_sha",
        "evidence_ref",
        "payload_sha256",
    )
    if not all(isinstance(envelope.get(key), str) for key in fields):
        return None
    attested = {key: envelope[key] for key in fields}
    return _canonical_json_bytes(attested)


def _structured_result_is_bound(
    evidence: WorkflowEvidence,
    workflow_result_verifier: WorkflowResultVerifier | None,
) -> bool:
    """Return whether a structured result has strict schema and provenance binding."""
    envelope = evidence.structured_result
    if workflow_result_verifier is None or not isinstance(envelope, Mapping):
        return False
    family = detector_family_for_job(evidence.job_name, evidence.workflow_name)
    if family == "unregistered":
        return False
    required = {
        "schema",
        "producer",
        "run_id",
        "head_sha",
        "evidence_ref",
        "payload_sha256",
        "attestation",
    }
    if set(envelope) != required | {"payload"}:
        return False
    if not all(
        isinstance(envelope.get(key), str) and envelope[key] for key in required
    ):
        return False
    if envelope["schema"] != "appguardrail.workflow-result-envelope.v1":
        return False
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping):
        return False
    if payload.get("schema") != "appguardrail.workflow-result.v1":
        return False
    outcome = payload.get("outcome")
    if not isinstance(outcome, str) or outcome not in {
        "clean",
        "control_blocked",
        "finding",
        "operational_failure",
    }:
        return False
    payload_fields = {
        "clean": {"schema", "outcome"},
        "control_blocked": {"schema", "outcome"},
        "finding": {"schema", "outcome", "detector_id", "rule_id"},
        "operational_failure": {"schema", "outcome", "cause_class"},
    }
    if set(payload) != payload_fields[outcome]:
        return False
    if outcome == "operational_failure" and not _IDENTIFIER_RE.fullmatch(
        _text_or_empty(payload.get("cause_class"))
    ):
        return False
    if outcome == "operational_failure" and payload["cause_class"] not in (
        _OPERATIONAL_CAUSES_BY_FAMILY.get(family, set())
    ):
        return False
    run_id = _text_or_empty(evidence.run_id)
    head_sha = _text_or_empty(evidence.head_sha)
    if not run_id or envelope["run_id"] != run_id:
        return False
    if not _SHA_RE.fullmatch(head_sha):
        return False
    if envelope["head_sha"].casefold() != head_sha.casefold():
        return False
    if not _DIGEST_RE.fullmatch(envelope["payload_sha256"]):
        return False
    canonical_payload = _canonical_json_bytes(payload)
    if canonical_payload is None:
        return False
    actual_digest = hashlib.sha256(canonical_payload).hexdigest()
    if envelope["payload_sha256"].casefold() != actual_digest:
        return False
    if envelope["producer"].casefold() not in _PRODUCERS_BY_FAMILY.get(family, set()):
        return False
    if not workflow_result_verifier.verify(envelope):
        return False
    if payload["outcome"] == "finding":
        return bool(
            isinstance(payload.get("detector_id"), str)
            and _IDENTIFIER_RE.fullmatch(payload["detector_id"])
            and isinstance(payload.get("rule_id"), str)
            and _IDENTIFIER_RE.fullmatch(payload["rule_id"])
        )
    return True


def _structured_result_detection(
    evidence: WorkflowEvidence,
    workflow_result_verifier: WorkflowResultVerifier | None,
) -> DetectionResult | None:
    """Convert one provenance-bound result, or fail closed when it is malformed."""
    if evidence.structured_result is None:
        return None
    if not _structured_result_is_bound(evidence, workflow_result_verifier):
        return _result(
            evidence,
            detector_id="workflow.structured_result_invalid",
            status="inconclusive",
            cause_class="invalid_or_unbound_structured_result",
            deploy_blocking=False,
            gate_satisfied=False,
            confirmed_security_finding=None,
            confidence="structured_result_rejected",
        )

    envelope = evidence.structured_result
    payload = envelope["payload"]
    outcome = str(payload["outcome"])
    if outcome == "finding":
        return _result(
            evidence,
            detector_id=str(payload["detector_id"]),
            status="finding",
            cause_class="expected_finding_block",
            deploy_blocking=True,
            gate_satisfied=False,
            confirmed_security_finding=True,
            confidence="structured_result",
        )
    if outcome == "clean":
        return _result(
            evidence,
            detector_id="workflow.structured_clean",
            status="clean",
            cause_class="verified_no_finding",
            deploy_blocking=False,
            gate_satisfied=_text_or_empty(evidence.conclusion).casefold()
            == "success",
            confirmed_security_finding=False,
            confidence="structured_result",
        )
    if outcome == "control_blocked":
        return _result(
            evidence,
            detector_id="workflow.structured_control_block",
            status="control_blocked",
            cause_class="expected_policy_block",
            deploy_blocking=False,
            gate_satisfied=False,
            confirmed_security_finding=False,
            confidence="structured_result",
        )
    return _result(
        evidence,
        detector_id="workflow.structured_operational_failure",
        status="dependency_failure",
        cause_class=_text_or_empty(payload["cause_class"]),
        deploy_blocking=False,
        gate_satisfied=False,
        confirmed_security_finding=None,
        confidence="structured_result",
    )


def detect_workflow_causes(
    evidence: WorkflowEvidence,
    *,
    workflow_result_verifier: WorkflowResultVerifier | None = None,
) -> tuple[DetectionResult, ...]:
    """Detect every independently actionable cause retained by one workflow issue."""
    text = evidence.log_text if isinstance(evidence.log_text, str) else ""
    job_name = _text_or_empty(evidence.job_name)
    conclusion = _text_or_empty(evidence.conclusion).casefold()
    results: list[DetectionResult] = []

    if _DISPATCH_REJECTION_RE.search(text):
        results.append(
            _result(
                evidence,
                detector_id="control.repository_dispatch_rejection_observed",
                status="inconclusive",
                cause_class="unverified_policy_block_observation",
                deploy_blocking=False,
                gate_satisfied=False,
                confirmed_security_finding=None,
                confidence="authorized_log",
            )
        )

    structured = _structured_result_detection(evidence, workflow_result_verifier)
    if structured is not None:
        if structured.detector_id == "workflow.structured_result_invalid":
            return (structured,)
        results.append(structured)

    confirmed_from_structure = bool(
        structured is not None and structured.confirmed_security_finding is True
    )
    if _REQUEST_CHANGES_RE.search(text) and not confirmed_from_structure:
        prefix = (
            "noema" if "noema" in job_name.casefold() else "opencode"
        )
        results.append(
            _result(
                evidence,
                detector_id=f"{prefix}.change_request_observed",
                status="inconclusive",
                cause_class="expected_finding_block",
                deploy_blocking=False,
                gate_satisfied=False,
                confirmed_security_finding=None,
            )
        )
    elif _POSITIVE_VULNERABILITY_RE.search(text) and not confirmed_from_structure:
        results.append(
            _result(
                evidence,
                detector_id="scanner.vulnerability_count_observed",
                status="inconclusive",
                cause_class="expected_finding_block",
                deploy_blocking=False,
                gate_satisfied=False,
                confirmed_security_finding=None,
            )
        )

    if _RATE_LIMIT_RE.search(text):
        results.append(
            _result(
                evidence,
                detector_id="provider.rate_limit",
                status="dependency_failure",
                cause_class="provider_rate_limit",
                deploy_blocking=False,
                gate_satisfied=False,
                confirmed_security_finding=(
                    False if _ZERO_VULNERABILITY_RE.search(text) else None
                ),
            )
        )

    if _PUBLICATION_DENIED_RE.search(text):
        results.append(
            _result(
                evidence,
                detector_id="github.publication_permission_denied",
                status="reporting_failed",
                cause_class="permission_auth",
                deploy_blocking=False,
                gate_satisfied=False,
                confirmed_security_finding=None,
            )
        )

    if "coverage" in job_name.casefold() and _COVERAGE_BLOCK_RE.search(text):
        results.append(
            _result(
                evidence,
                detector_id="control.coverage_evidence_rejected",
                status="control_blocked",
                cause_class="threshold_or_evidence_failure",
                deploy_blocking=False,
                gate_satisfied=False,
                confirmed_security_finding=False,
            )
        )

    if not results and (
        conclusion == "timed_out" or _TIMEOUT_RE.search(text)
    ):
        results.append(
            _result(
                evidence,
                detector_id="workflow.execution_timeout",
                status="dependency_failure",
                cause_class="timeout",
                deploy_blocking=False,
                gate_satisfied=False,
                confirmed_security_finding=None,
            )
        )

    if not results and conclusion == "cancelled":
        results.append(
            _result(
                evidence,
                detector_id="workflow.cancelled_unclassified",
                status="inconclusive",
                cause_class="manual_or_superseded_cancel_or_unknown",
                deploy_blocking=False,
                gate_satisfied=False,
                confirmed_security_finding=None,
                confidence="metadata_only" if not text else "authorized_log",
            )
        )

    if not results:
        results.append(
            _result(
                evidence,
                detector_id="workflow.failure_unclassified",
                status="inconclusive",
                cause_class="unknown",
                deploy_blocking=False,
                gate_satisfied=False,
                confirmed_security_finding=None,
                confidence="metadata_only" if not text else "authorized_log",
            )
        )
    return tuple(results)


def load_issue_detection_registry(
    path: str | Path | None = None,
) -> IssueDetectionRegistry:
    """Load the committed exhaustive issue-to-detector registry."""
    source = Path(path) if path is not None else _REGISTRY_PATH
    payload = json.loads(source.read_text(encoding="utf-8"))
    _validate_registry_payload(payload)
    issues = tuple(
        IssueDetectionTarget(
            issue_number=int(item["issue_number"]),
            claims=tuple(
                IssueDetectionClaim(
                    claim_id=str(claim["claim_id"]),
                    detector_family=str(claim["detector_family"]),
                )
                for claim in item["claims"]
            ),
            requirement_sha256=str(item["requirement_sha256"]),
            issue_updated_at=str(item["issue_updated_at"]),
            retained_detection_requirement=bool(
                item["retained_detection_requirement"]
            ),
        )
        for item in payload["issues"]
    )
    return IssueDetectionRegistry(
        schema=str(payload["schema"]),
        repository=str(payload["repository"]),
        inventory_as_of=str(payload["inventory_as_of"]),
        issue_count=int(payload["issue_count"]),
        detector_families=payload["detector_families"],
        issues=issues,
    )


def _registry_field_names(value: Any) -> tuple[str, ...]:
    """Return every nested registry field name for no-waiver validation."""
    names: list[str] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            names.append(str(key).casefold())
            names.extend(_registry_field_names(nested))
    elif isinstance(value, list):
        for nested in value:
            names.extend(_registry_field_names(nested))
    return tuple(names)


def _require_registry(condition: bool, message: str) -> None:
    """Raise a stable validation error when a registry invariant is broken."""
    if not condition:
        raise ValueError(message)


def _is_nonempty_string_list(value: Any) -> bool:
    """Return whether a registry field is a unique non-empty string list."""
    return bool(
        isinstance(value, list)
        and value
        and all(isinstance(item, str) and item for item in value)
        and len(value) == len(set(value))
    )


def _valid_obligation_contract(
    obligation: Any,
    evidence_fields: set[str],
    required_fields: set[str],
) -> bool:
    """Validate one executable three-way detector obligation."""
    if not isinstance(obligation, Mapping):
        return False
    allowed_keys = {
        "fixtures",
        "obligation_id",
        "positive_status",
        "required_evidence_fields",
    }
    if set(obligation) - allowed_keys or not {
        "fixtures",
        "obligation_id",
        "required_evidence_fields",
    } <= set(obligation):
        return False
    obligation_id = obligation.get("obligation_id")
    obligation_fields = obligation.get("required_evidence_fields")
    positive_status = obligation.get("positive_status", "detected")
    fixtures = obligation.get("fixtures")
    if (
        not isinstance(obligation_id, str)
        or not _IDENTIFIER_RE.fullmatch(obligation_id)
        or not _is_nonempty_string_list(obligation_fields)
        or not set(obligation_fields) <= required_fields
        or positive_status not in {"clean", "detected", "unknown"}
        or not isinstance(fixtures, Mapping)
        or set(fixtures)
        != {"negative_patch", "positive_patch", "unknown_remove_fields"}
    ):
        return False
    positive = fixtures.get("positive_patch")
    negative = fixtures.get("negative_patch")
    unknown = fixtures.get("unknown_remove_fields")
    return bool(
        isinstance(positive, Mapping)
        and positive
        and isinstance(negative, Mapping)
        and all(isinstance(key, str) for key in positive)
        and all(isinstance(key, str) for key in negative)
        and set(positive) <= evidence_fields
        and set(negative) <= evidence_fields
        and _is_nonempty_string_list(unknown)
        and set(unknown) <= set(obligation_fields)
    )


def _validate_registry_payload(payload: Any) -> None:
    """Fail closed unless an exhaustive no-waiver detector registry is valid."""
    _require_registry(isinstance(payload, Mapping), "registry must be an object")
    _require_registry(
        payload.get("schema") == "appguardrail.issue-detection-registry.v1",
        "unsupported issue detection registry schema",
    )
    _require_registry(
        payload.get("repository") == "ContextualWisdomLab/appguardrail",
        "registry repository identity does not match AppGuardrail",
    )
    forbidden = _FORBIDDEN_REGISTRY_FIELDS.intersection(
        _registry_field_names(payload)
    )
    _require_registry(
        not forbidden,
        "forbidden registry field: " + ", ".join(sorted(forbidden)),
    )

    families = payload.get("detector_families")
    raw_issues = payload.get("issues")
    _require_registry(
        isinstance(families, Mapping) and bool(families),
        "detector_families must be a non-empty object",
    )
    _require_registry(
        set(families) == set(_FAMILY_ADAPTERS),
        "registry families must exactly match callable adapters",
    )
    _require_registry(isinstance(raw_issues, list), "issues must be an array")
    _require_registry(
        all(
            isinstance(contract, Mapping)
            and _REQUIRED_FAMILY_FIELDS <= set(contract)
            for contract in families.values()
        ),
        "every detector family must define its executable contract",
    )
    _require_registry(
        all(
            contract["adapter_id"] == family
            and contract["adapter_ref"]
            == (
                "appguardrail_core.issue_detection:"
                + _FAMILY_ADAPTERS[family].__name__
            )
            and contract["no_exclusions"] is True
            and isinstance(contract["evidence_schema"], str)
            and bool(contract["evidence_schema"])
            and isinstance(contract["implementation_refs"], list)
            and bool(contract["implementation_refs"])
            and all(
                isinstance(reference, str)
                and bool(_IMPLEMENTATION_REF_RE.fullmatch(reference))
                for reference in contract["implementation_refs"]
            )
            for family, contract in families.items()
        ),
        "every family must bind its callable adapter reference and "
        "implementation references",
    )
    _require_registry(
        all(
            _is_nonempty_string_list(contract["evidence_fields"])
            and _is_nonempty_string_list(contract["required_evidence_fields"])
            and set(contract["required_evidence_fields"])
            <= set(contract["evidence_fields"])
            and "schema" in contract["required_evidence_fields"]
            and isinstance(contract["obligations"], list)
            and bool(contract["obligations"])
            and len(contract["obligations"])
            == len(
                {
                    obligation.get("obligation_id")
                    for obligation in contract["obligations"]
                    if isinstance(obligation, Mapping)
                }
            )
            and all(
                _valid_obligation_contract(
                    obligation,
                    set(contract["evidence_fields"]),
                    set(contract["required_evidence_fields"]),
                )
                for obligation in contract["obligations"]
            )
            for contract in families.values()
        ),
        "every family must define closed evidence and executable obligations",
    )
    _require_registry(
        all(
            isinstance(contract["outcome_states"], Mapping)
            and set(contract["outcome_states"])
            == {"clean", "detected", "unknown"}
            and all(
                isinstance(states, list) and bool(states)
                for states in contract["outcome_states"].values()
            )
            and isinstance(contract["fixtures"], Mapping)
            and set(contract["fixtures"])
            == {"negative", "positive", "unknown"}
            and all(
                isinstance(fixture, Mapping)
                for fixture in contract["fixtures"].values()
            )
            and all(
                set(fixture) <= set(contract["evidence_fields"])
                for fixture in contract["fixtures"].values()
            )
            and all(
                set(contract["required_evidence_fields"]) <= set(fixture)
                for name, fixture in contract["fixtures"].items()
                if name in {"positive", "negative"}
            )
            and "state" not in _registry_field_names(contract["fixtures"])
            for contract in families.values()
        ),
        "every family must define raw evidence fixtures for detected, clean, "
        "and unknown",
    )
    _require_registry(
        all(
            isinstance(item, Mapping)
            and set(item)
            == {
                "claims",
                "issue_number",
                "issue_updated_at",
                "requirement_sha256",
                "retained_detection_requirement",
            }
            and isinstance(item["claims"], list)
            and bool(item["claims"])
            and isinstance(item["issue_updated_at"], str)
            and bool(item["issue_updated_at"])
            and bool(_DIGEST_RE.fullmatch(str(item["requirement_sha256"])))
            and all(
                isinstance(claim, Mapping)
                and set(claim) == {"claim_id", "detector_family"}
                and isinstance(claim["claim_id"], str)
                and bool(claim["claim_id"])
                for claim in item["claims"]
            )
            for item in raw_issues
        ),
        "issue mappings must use the closed no-waiver schema",
    )

    issue_numbers = [int(item["issue_number"]) for item in raw_issues]
    _require_registry(
        issue_numbers == sorted(set(issue_numbers)),
        "issue numbers must be unique and strictly increasing",
    )
    _require_registry(
        int(payload.get("issue_count", -1)) == len(raw_issues),
        "issue_count must equal the explicit issue mapping count",
    )
    _require_registry(
        all(item["retained_detection_requirement"] is True for item in raw_issues),
        "every issue must remain a retained detection requirement",
    )
    _require_registry(
        all(
            claim["detector_family"] in families
            for item in raw_issues
            for claim in item["claims"]
        ),
        "issue mapping references an unknown detector family",
    )
    _require_registry(
        all(
            len({claim["claim_id"] for claim in item["claims"]})
            == len(item["claims"])
            for item in raw_issues
        ),
        "claim identifiers must be unique within each issue",
    )


def audit_issue_coverage(
    live_issue_numbers: Iterable[int],
    registry: IssueDetectionRegistry,
) -> IssueCoverageAudit:
    """Compare live issue identities with retained registered requirements."""
    live = {int(number) for number in live_issue_numbers}
    registered = {target.issue_number for target in registry.issues}
    return IssueCoverageAudit(
        unmapped_issue_numbers=tuple(sorted(live - registered)),
        registry_only_issue_numbers=tuple(sorted(registered - live)),
    )


def compute_issue_requirement_sha256(title: Any, body: Any) -> str:
    """Hash normalized title/body requirement text without retaining the text."""
    normalized = {
        "body": _text_or_empty(body).replace("\r\n", "\n").strip(),
        "title": _text_or_empty(title).replace("\r\n", "\n").strip(),
    }
    canonical = _canonical_json_bytes(normalized)
    if canonical is None:
        canonical = json.dumps(
            normalized,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def audit_issue_requirements(
    live_requirements: Mapping[int, str | None],
    registry: IssueDetectionRegistry,
) -> IssueCoverageAudit:
    """Compare live issue identity and requirement digests with the registry."""
    identity_audit = audit_issue_coverage(live_requirements, registry)
    registered = {target.issue_number: target for target in registry.issues}
    common = set(live_requirements).intersection(registered)
    incomplete = tuple(
        sorted(number for number in common if live_requirements[number] is None)
    )
    changed = tuple(
        sorted(
            number
            for number in common
            if live_requirements[number] is not None
            and live_requirements[number] != registered[number].requirement_sha256
        )
    )
    return IssueCoverageAudit(
        unmapped_issue_numbers=identity_audit.unmapped_issue_numbers,
        registry_only_issue_numbers=identity_audit.registry_only_issue_numbers,
        changed_issue_numbers=changed,
        incomplete_issue_numbers=incomplete,
    )


def _looks_like_pull_request(value: Mapping[str, Any]) -> bool:
    """Recognize REST and connector-normalized pull-request records."""
    if "pull_request" in value:
        return True
    urls = (value.get("url"), value.get("html_url"), value.get("display_url"))
    return any(
        "/pull/" in url or "/pulls/" in url
        for url in urls
        if isinstance(url, str)
    )


def _issue_requirements_from_github_payload(
    payload: Any,
) -> dict[int, str | None]:
    """Extract issue identities and requirement digests from paginated responses."""
    requirements: dict[int, str | None] = {}

    def visit(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, dict):
            return
        number_key = (
            "number"
            if "number" in value
            else "issue_number" if "issue_number" in value else ""
        )
        if number_key:
            if not _looks_like_pull_request(value):
                number = int(value[number_key])
                supplied_digest = str(value.get("requirement_sha256", ""))
                digest = (
                    compute_issue_requirement_sha256(
                        value.get("title"), value.get("body")
                    )
                    if "title" in value and "body" in value
                    else supplied_digest.casefold()
                    if _DIGEST_RE.fullmatch(supplied_digest)
                    else None
                )
                if number in requirements and requirements[number] != digest:
                    requirements[number] = None
                else:
                    requirements[number] = digest
            return
        for nested in value.values():
            visit(nested)

    visit(payload)
    return dict(sorted(requirements.items()))


def _issue_numbers_from_github_payload(payload: Any) -> tuple[int, ...]:
    """Extract issue identities from flat or paginated GitHub issues responses."""
    return tuple(_issue_requirements_from_github_payload(payload))


def _build_parser() -> argparse.ArgumentParser:
    """Build the issue-detection command parser."""
    parser = argparse.ArgumentParser(
        prog="appguardrail-issue-detection",
        description="Classify issue-derived evidence and audit detector coverage.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    classify = commands.add_parser(
        "classify-workflow",
        help="Classify one authorized workflow log without echoing it.",
    )
    classify.add_argument("--workflow-name", required=True)
    classify.add_argument("--job-name", required=True)
    classify.add_argument("--conclusion", required=True)
    classify.add_argument("--run-id", default="")
    classify.add_argument("--head-sha", default="")
    classify.add_argument("--result-file")
    classify.add_argument(
        "--log-file",
        default="-",
        help="Authorized log path, or '-' for standard input.",
    )

    audit = commands.add_parser(
        "audit-registry",
        help="Compare GitHub's complete issue inventory with the registry.",
    )
    audit.add_argument("--issues-file", required=True)
    audit.add_argument("--registry")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Run the installed issue-detection command."""
    args = _build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout

    if args.command == "classify-workflow":
        log_text = (
            input_stream.read()
            if args.log_file == "-"
            else Path(args.log_file).read_text(encoding="utf-8")
        )
        structured_result = (
            json.loads(Path(args.result_file).read_text(encoding="utf-8"))
            if args.result_file
            else None
        )
        workflow_result_verifier = None
        encoded_attestation_key = os.environ.get(_RESULT_ATTESTATION_KEY_ENV, "")
        if structured_result is not None and encoded_attestation_key:
            try:
                workflow_result_verifier = WorkflowResultVerifier.from_base64(
                    encoded_attestation_key
                )
            except ValueError:
                workflow_result_verifier = None
        detections = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name=args.workflow_name,
                job_name=args.job_name,
                conclusion=args.conclusion,
                log_text=log_text,
                run_id=args.run_id,
                head_sha=args.head_sha,
                structured_result=structured_result,
            ),
            workflow_result_verifier=workflow_result_verifier,
        )
        payload = {
            "schema": "appguardrail.issue-detections.v1",
            "detections": [detection.as_dict() for detection in detections],
        }
        json.dump(payload, output_stream, sort_keys=True)
        output_stream.write("\n")
        return 0

    registry = load_issue_detection_registry(args.registry)
    issues_payload = json.loads(
        Path(args.issues_file).read_text(encoding="utf-8")
    )
    live_requirements = _issue_requirements_from_github_payload(issues_payload)
    audit = audit_issue_requirements(live_requirements, registry)
    payload = {
        "changed_issue_numbers": list(audit.changed_issue_numbers),
        "complete": audit.complete,
        "incomplete_issue_numbers": list(audit.incomplete_issue_numbers),
        "live_issue_count": len(live_requirements),
        "registry_issue_count": registry.issue_count,
        "registry_only_issue_numbers": list(audit.registry_only_issue_numbers),
        "schema": "appguardrail.issue-coverage-audit.v1",
        "unmapped_issue_numbers": list(audit.unmapped_issue_numbers),
    }
    json.dump(payload, output_stream, sort_keys=True)
    output_stream.write("\n")
    return 0 if audit.complete else 1


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())  # pragma: no cover
