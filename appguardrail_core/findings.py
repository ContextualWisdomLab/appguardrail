"""Normalized finding contract shared across AppGuardrail surfaces."""

from __future__ import annotations

from typing import Any, Iterable

SEVERITIES = ("CRITICAL", "HIGH", "WARNING", "INFO")
DEPLOY_BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
NON_BLOCKING_CONTEXTS = {"doc", "test", "example", "scanner-fixture"}

_SEVERITY_ORDER = {severity: index for index, severity in enumerate(SEVERITIES)}


def normalize_finding(
    finding: dict[str, Any],
    *,
    snippet_max_len: int = 400,
) -> dict[str, Any]:
    """Return a normalized, report-safe AppGuardrail finding dictionary."""
    normalized = dict(finding)
    normalized["severity"] = str(normalized.get("severity") or "INFO").upper()
    normalized["rule_id"] = str(normalized.get("rule_id") or "unknown-rule")
    normalized["message"] = str(normalized.get("message") or "No message provided.")
    normalized["file"] = str(normalized.get("file") or "n/a")
    normalized["line"] = normalized.get("line") or 1
    normalized["category"] = str(normalized.get("category") or "misconfig")
    normalized["context"] = str(normalized.get("context") or "app-code")
    normalized["references"] = _as_tuple(normalized.get("references"))
    normalized["owasp"] = _as_tuple(normalized.get("owasp"))
    normalized["cwe"] = _as_tuple(normalized.get("cwe"))
    normalized["remediation"] = str(
        normalized.get("remediation")
        or normalized.get("fix_prompt")
        or "Review and remediate this finding, then rerun AppGuardrail."
    )
    normalized["verification"] = str(
        normalized.get("verification") or "Rerun AppGuardrail after remediation."
    )
    normalized["snippet"] = safe_report_snippet(
        str(normalized.get("snippet") or ""), max_len=snippet_max_len
    )
    return normalized


def normalize_findings(
    findings: Iterable[dict[str, Any]],
    *,
    snippet_max_len: int = 400,
) -> tuple[dict[str, Any], ...]:
    """Normalize a finding collection into a stable tuple."""
    return tuple(
        normalize_finding(finding, snippet_max_len=snippet_max_len)
        for finding in findings
    )


def severity_counts(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Count normalized severities, folding unknown values into INFO."""
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity") or "INFO").upper()
        counts[severity if severity in counts else "INFO"] += 1
    return counts


def is_deploy_blocking(finding: dict[str, Any]) -> bool:
    """Return whether a finding should fail a deploy gate."""
    severity = str(finding.get("severity") or "INFO").upper()
    context = str(finding.get("context") or "app-code")
    return severity in DEPLOY_BLOCKING_SEVERITIES and context not in NON_BLOCKING_CONTEXTS


def finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, str]:
    """Sort by deploy-oriented severity, then category and rule id."""
    severity = str(finding.get("severity") or "INFO").upper()
    return (
        _SEVERITY_ORDER.get(severity, len(SEVERITIES)),
        str(finding.get("category") or "misconfig"),
        str(finding.get("rule_id") or "unknown-rule"),
    )


def safe_report_snippet(snippet: str, max_len: int = 400) -> str:
    """Trim report evidence without carrying oversized raw snippets."""
    snippet = snippet.replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(snippet) <= max_len:
        return snippet
    return snippet[:max_len].rstrip() + "\n...[truncated]"


def _as_tuple(value: Any) -> tuple[str, ...]:
    if not value:
        return ()
    if isinstance(value, str):
        return (value,)
    try:
        return tuple(str(item) for item in value)
    except TypeError:
        return (str(value),)
