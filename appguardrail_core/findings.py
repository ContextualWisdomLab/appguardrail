"""Normalized finding contract shared across AppGuardrail surfaces."""

from __future__ import annotations

from typing import Any, Iterable

SEVERITIES = ("CRITICAL", "HIGH", "WARNING", "INFO")
DEPLOY_BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
NON_BLOCKING_CONTEXTS = {"doc", "test", "example", "scanner-fixture"}

_SEVERITY_ORDER = {severity: index for index, severity in enumerate(SEVERITIES)}
_SEV_SET = set(SEVERITIES)


def normalize_finding(
    finding: dict[str, Any],
    *,
    snippet_max_len: int = 400,
) -> dict[str, Any]:
    """Return a normalized, report-safe AppGuardrail finding dictionary."""
    normalized = dict(finding)

    sev = normalized.get("severity")
    if type(sev) is not str or sev not in _SEV_SET:
        normalized["severity"] = str(sev or "INFO").upper()

    rule = normalized.get("rule_id")
    if type(rule) is not str or not rule:
        normalized["rule_id"] = str(rule or "unknown-rule")

    msg = normalized.get("message")
    if type(msg) is not str or not msg:
        normalized["message"] = str(msg or "No message provided.")

    file = normalized.get("file")
    if type(file) is not str or not file:
        normalized["file"] = str(file or "n/a")

    if not normalized.get("line"):
        normalized["line"] = 1

    cat = normalized.get("category")
    if type(cat) is not str or not cat:
        normalized["category"] = str(cat or "misconfig")

    ctx = normalized.get("context")
    if type(ctx) is not str or not ctx:
        normalized["context"] = str(ctx or "app-code")

    normalized["references"] = _as_tuple(normalized.get("references"))
    normalized["owasp"] = _as_tuple(normalized.get("owasp"))
    normalized["cwe"] = _as_tuple(normalized.get("cwe"))

    rem = normalized.get("remediation")
    if not rem:
        rem = normalized.get("fix_prompt")
    if type(rem) is not str or not rem:
        normalized["remediation"] = str(
            rem or "Review and remediate this finding, then rerun AppGuardrail."
        )
    elif rem != normalized.get("remediation"):
        normalized["remediation"] = rem

    verif = normalized.get("verification")
    if type(verif) is not str or not verif:
        normalized["verification"] = str(
            verif or "Rerun AppGuardrail after remediation."
        )

    snip = normalized.get("snippet")
    if type(snip) is not str or not snip:
        snip = str(snip or "")
    normalized["snippet"] = safe_report_snippet(snip, max_len=snippet_max_len)

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
        sev = finding.get("severity")
        if type(sev) is not str or sev not in _SEVERITY_ORDER:
            sev = str(sev or "INFO").upper()
            if sev not in _SEVERITY_ORDER:
                sev = "INFO"
        counts[sev] += 1
    return counts


def is_deploy_blocking(
    finding: dict[str, Any],
    blocking_severities: "set[str] | None" = None,
) -> bool:
    """Return whether a finding should fail a deploy gate.

    ``blocking_severities`` overrides the default CRITICAL/HIGH set, letting a
    config raise or lower the gate threshold (see ``severities_at_or_above``).
    """
    severities = blocking_severities or DEPLOY_BLOCKING_SEVERITIES

    sev = finding.get("severity")
    if type(sev) is not str or sev not in _SEVERITY_ORDER:
        sev = str(sev or "INFO").upper()

    ctx = finding.get("context")
    if type(ctx) is not str or not ctx:
        ctx = str(ctx or "app-code")

    return sev in severities and ctx not in NON_BLOCKING_CONTEXTS


def severities_at_or_above(min_severity: str) -> set[str]:
    """Severity names at or above ``min_severity`` (CRITICAL is highest)."""
    idx = _SEVERITY_ORDER.get(str(min_severity).upper())
    if idx is None:
        return set(DEPLOY_BLOCKING_SEVERITIES)
    return {sev for sev, order in _SEVERITY_ORDER.items() if order <= idx}


def finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, str]:
    """Sort by deploy-oriented severity, then category and rule id."""
    sev = finding.get("severity")
    if type(sev) is not str or sev not in _SEVERITY_ORDER:
        sev = str(sev or "INFO").upper()

    cat = finding.get("category")
    if type(cat) is not str or not cat:
        cat = str(cat or "misconfig")

    rule = finding.get("rule_id")
    if type(rule) is not str or not rule:
        rule = str(rule or "unknown-rule")

    return (
        _SEVERITY_ORDER.get(sev, len(SEVERITIES)),
        cat,
        rule,
    )


def safe_report_snippet(snippet: str, max_len: int = 400) -> str:
    """Trim report evidence without carrying oversized raw snippets."""
    if not snippet:
        return ""
    snippet = snippet.replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(snippet) <= max_len:
        return snippet
    return snippet[:max_len].rstrip() + "\n...[truncated]"


def _as_tuple(value: Any) -> tuple[str, ...]:
    if not value:
        return ()
    if type(value) is str:
        return (value,)
    try:
        return tuple(item if type(item) is str else str(item) for item in value)
    except TypeError:
        return (str(value),)
