"""Normalized finding contract shared across AppGuardrail surfaces."""

from __future__ import annotations

from typing import Any, Iterable

SEVERITIES = ("CRITICAL", "HIGH", "WARNING", "INFO")
DEPLOY_BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
NON_BLOCKING_CONTEXTS = {"doc", "test", "example", "scanner-fixture"}

_SEVERITY_ORDER = {severity: index for index, severity in enumerate(SEVERITIES)}
_SEV_SET = frozenset(SEVERITIES)


def normalize_finding(
    finding: dict[str, Any],
    *,
    snippet_max_len: int = 400,
) -> dict[str, Any]:
    """Return a normalized, report-safe AppGuardrail finding dictionary."""
    normalized = dict(finding)

    sev = normalized.get("severity")
    if type(sev) is not str or sev not in _SEV_SET:
        try:
            normalized["severity"] = str(sev or "INFO").upper()
        except Exception:
            normalized["severity"] = "INFO"

    rule = normalized.get("rule_id")
    if type(rule) is not str or not rule:
        try:
            normalized["rule_id"] = str(rule or "unknown-rule")
        except Exception:
            normalized["rule_id"] = "unknown-rule"

    msg = normalized.get("message")
    if type(msg) is not str or not msg:
        try:
            normalized["message"] = str(msg or "No message provided.")
        except Exception:
            normalized["message"] = "No message provided."

    file = normalized.get("file")
    if type(file) is not str or not file:
        try:
            normalized["file"] = str(file or "n/a")
        except Exception:
            normalized["file"] = "n/a"

    if not normalized.get("line"):
        normalized["line"] = 1

    cat = normalized.get("category")
    if type(cat) is not str or not cat:
        try:
            normalized["category"] = str(cat or "misconfig")
        except Exception:
            normalized["category"] = "misconfig"

    ctx = normalized.get("context")
    if type(ctx) is not str or not ctx:
        try:
            normalized["context"] = str(ctx or "app-code")
        except Exception:
            normalized["context"] = "app-code"

    normalized["references"] = _as_tuple(normalized.get("references"))
    normalized["owasp"] = _as_tuple(normalized.get("owasp"))
    normalized["cwe"] = _as_tuple(normalized.get("cwe"))

    rem = normalized.get("remediation")
    if not rem:
        rem = normalized.get("fix_prompt")
    if type(rem) is not str or not rem:
        try:
            normalized["remediation"] = str(
                rem or "Review and remediate this finding, then rerun AppGuardrail."
            )
        except Exception:
            normalized["remediation"] = "Review and remediate this finding, then rerun AppGuardrail."
    elif rem != normalized.get("remediation"):
        normalized["remediation"] = rem

    verif = normalized.get("verification")
    if type(verif) is not str or not verif:
        try:
            normalized["verification"] = str(verif or "Rerun AppGuardrail after remediation.")
        except Exception:
            normalized["verification"] = "Rerun AppGuardrail after remediation."

    snip = normalized.get("snippet")
    if type(snip) is not str or not snip:
        try:
            snip = str(snip or "")
        except Exception:
            snip = ""
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
            try:
                sev = str(sev or "INFO").upper()
            except Exception:
                sev = "INFO"
            if type(sev) is not str or sev not in _SEVERITY_ORDER:
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
        try:
            sev = str(sev or "INFO").upper()
        except Exception:
            sev = "INFO"

    ctx = finding.get("context")
    if type(ctx) is not str or not ctx:
        try:
            ctx = str(ctx or "app-code")
        except Exception:
            ctx = "app-code"

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
        try:
            sev = str(sev or "INFO").upper()
        except Exception:
            sev = "INFO"

    cat = finding.get("category")
    if type(cat) is not str or not cat:
        try:
            cat = str(cat or "misconfig")
        except Exception:
            cat = "misconfig"

    rule = finding.get("rule_id")
    if type(rule) is not str or not rule:
        try:
            rule = str(rule or "unknown-rule")
        except Exception:
            rule = "unknown-rule"

    return (
        _SEVERITY_ORDER.get(sev, len(SEVERITIES)),
        cat,
        rule,
    )


def safe_report_snippet(snippet: str, max_len: int = 400) -> str:
    """Trim report evidence without carrying oversized raw snippets."""
    if type(snippet) is not str:
        try:
            snippet = str(snippet or "")
        except Exception:
            snippet = ""
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
        iterator = iter(value)
    except Exception:
        try:
            return (str(value),)
        except Exception:
            return ()

    items: list[str] = []
    try:
        for item in iterator:
            if type(item) is str:
                items.append(item)
                continue
            try:
                items.append(str(item))
            except Exception:
                continue
    except Exception:
        return tuple(items)
    return tuple(items)
