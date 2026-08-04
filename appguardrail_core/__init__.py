"""Reusable AppGuardrail core helpers."""

from __future__ import annotations

from typing import Any, Iterable

from appguardrail_core import reports as _reports
from appguardrail_core.audit_events import (
    GENESIS_EVENT_HASH,
    AuditEvent,
    create_audit_event,
    recompute_event_hash,
    sanitize_audit_summary,
    verify_audit_chain,
)
from appguardrail_core.code_scanning import (
    AnalysisEvidence,
    AnalysisIdentity,
    AnalysisSnapshot,
    DriftAssessment,
    build_snapshot as build_code_scanning_snapshot,
    compare_snapshots as compare_code_scanning_snapshots,
    normalize_analysis as normalize_code_scanning_analysis,
)
from appguardrail_core.external import (
    ExternalEngineDecision,
    ExternalScanPlan,
    build_external_scan_plan,
)
from appguardrail_core.findings import (
    DEPLOY_BLOCKING_SEVERITIES,
    NON_BLOCKING_CONTEXTS,
    SEVERITIES,
    finding_sort_key,
    is_deploy_blocking,
    normalize_finding,
    normalize_findings,
    safe_report_snippet,
    severity_counts,
)
from appguardrail_core.language import (
    StackProfile,
    detect_language_axes,
    detect_stack_profile,
)
from appguardrail_core.metrics import (
    MetricResult,
    SaleReadinessInputs,
    SaleReadinessScore,
    score_sale_readiness,
)
from appguardrail_core.openssf_evidence import (
    OpenSSFEvidence,
    collect_openssf_evidence,
    evidence_to_finding,
    parse_project_matches as parse_openssf_project_matches,
)
from appguardrail_core.openssf_report import augment_buyer_diligence_report
from appguardrail_core.org_intelligence import (
    BuyerEvidenceMetric,
    BuyerEvidencePack,
    OrgInventory,
    PullRequestGateSummary,
    RepositoryGateSummary,
    build_buyer_evidence_pack,
    build_org_inventory,
    buyer_evidence_pack_to_dict,
    classify_pr_gate,
    gate_action_bucket,
    render_org_readiness_report,
    summarize_pr_gates,
)
from appguardrail_core.retention_policy import (
    DEFAULT_RETENTION_DAYS,
    MAX_RETENTION_DAYS,
    MIN_RETENTION_DAYS,
    RETENTION_CATEGORIES,
    PurgePreview,
    PurgeReceipt,
    RetentionPolicy,
    RetentionPolicyConflict,
    StalePurgePreview,
    build_purge_preview,
    create_purge_receipt,
    update_retention_policy,
    verify_purge_preview,
)
from appguardrail_core.rules import (
    RuleMetadata,
    build_rule_metadata,
    extract_public_references,
    validate_rule_metadata,
)


ReportContext = _reports.ReportContext
_BASE_RENDERER_ATTRIBUTE = "_openssf_base_buyer_diligence_renderer"
if not hasattr(_reports, _BASE_RENDERER_ATTRIBUTE):
    setattr(
        _reports,
        _BASE_RENDERER_ATTRIBUTE,
        _reports.render_buyer_diligence_report,
    )
_BASE_BUYER_DILIGENCE_RENDERER = getattr(_reports, _BASE_RENDERER_ATTRIBUTE)


def render_buyer_diligence_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render the standard buyer report with auditable OpenSSF evidence inserted."""
    materialized = list(findings)
    rendered = _BASE_BUYER_DILIGENCE_RENDERER(materialized, context)
    return augment_buyer_diligence_report(rendered, materialized)


# ``reports.render_report`` resolves this module global at call time. Installing
# the wrapper at the package boundary preserves the established report module
# while keeping the evidence vertical independently importable and testable.
# The original renderer is retained on the reports module so package reloads do
# not capture an earlier wrapper and recurse.
_reports.render_buyer_diligence_report = render_buyer_diligence_report


__all__ = [
    "AnalysisEvidence",
    "AnalysisIdentity",
    "AnalysisSnapshot",
    "AuditEvent",
    "BuyerEvidenceMetric",
    "BuyerEvidencePack",
    "DEFAULT_RETENTION_DAYS",
    "DEPLOY_BLOCKING_SEVERITIES",
    "DriftAssessment",
    "ExternalEngineDecision",
    "ExternalScanPlan",
    "GENESIS_EVENT_HASH",
    "MAX_RETENTION_DAYS",
    "MIN_RETENTION_DAYS",
    "MetricResult",
    "NON_BLOCKING_CONTEXTS",
    "OpenSSFEvidence",
    "OrgInventory",
    "PurgePreview",
    "PurgeReceipt",
    "PullRequestGateSummary",
    "RETENTION_CATEGORIES",
    "ReportContext",
    "RepositoryGateSummary",
    "RetentionPolicy",
    "RetentionPolicyConflict",
    "RuleMetadata",
    "SEVERITIES",
    "SaleReadinessInputs",
    "SaleReadinessScore",
    "StackProfile",
    "StalePurgePreview",
    "build_buyer_evidence_pack",
    "build_code_scanning_snapshot",
    "build_external_scan_plan",
    "build_org_inventory",
    "build_purge_preview",
    "build_rule_metadata",
    "buyer_evidence_pack_to_dict",
    "classify_pr_gate",
    "collect_openssf_evidence",
    "compare_code_scanning_snapshots",
    "create_audit_event",
    "create_purge_receipt",
    "detect_language_axes",
    "detect_stack_profile",
    "evidence_to_finding",
    "extract_public_references",
    "finding_sort_key",
    "gate_action_bucket",
    "is_deploy_blocking",
    "normalize_code_scanning_analysis",
    "normalize_finding",
    "normalize_findings",
    "parse_openssf_project_matches",
    "recompute_event_hash",
    "render_buyer_diligence_report",
    "render_org_readiness_report",
    "safe_report_snippet",
    "sanitize_audit_summary",
    "score_sale_readiness",
    "severity_counts",
    "summarize_pr_gates",
    "update_retention_policy",
    "validate_rule_metadata",
    "verify_audit_chain",
    "verify_purge_preview",
]
