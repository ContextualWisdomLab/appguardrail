"""Normalized finding contract shared across AppGuardrail surfaces."""

from __future__ import annotations

from typing import Any, Iterable

from appguardrail_core.redaction import (
    redact_sensitive_prefix,
    redact_sensitive_text,
    redact_sensitive_value,
)

SEVERITIES = ("CRITICAL", "HIGH", "WARNING", "INFO")
DEPLOY_BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
NON_BLOCKING_CONTEXTS = {"doc", "test", "example", "scanner-fixture"}

_SEVERITY_ORDER = {severity: index for index, severity in enumerate(SEVERITIES)}
_SEV_SET = frozenset(SEVERITIES)
_SENSITIVE_RULE_SEGMENTS = frozenset({"hardcoded"})
_SENSITIVE_ASSET_SEGMENTS = frozenset(
    {
        "credential",
        "credentials",
        "jwt",
        "password",
        "secret",
        "secrets",
        "token",
    }
)
_SENSITIVE_DISCLOSURE_SEGMENTS = frozenset(
    {"checked", "committed", "disclosure", "exposure", "leak", "leaked"}
)
_SENSITIVE_RULE_IDS = frozenset(
    {
        "env-file-with-secrets-committed",
        "next-public-secret",
        "nextjs-env-secret-client-prefix",
        "stripe-secret-key-client-exposure",
    }
)
_REDACTED_SENSITIVE_SNIPPET = "[REDACTED: sensitive match suppressed]"
_REDACTION_LOOKAHEAD = 128


def normalize_finding(
    finding: dict[str, Any],
    *,
    snippet_max_len: int = 400,
) -> dict[str, Any]:
    """Return a normalized, report-safe AppGuardrail finding dictionary."""
    untrusted_finding = dict(finding)
    untrusted_snippet = untrusted_finding.pop("snippet", "")
    normalized = redact_sensitive_value(untrusted_finding)

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

    line = normalized.get("line")
    if type(line) is int and line > 0:
        normalized["line"] = line
    elif (
        type(line) is str
        and len(line) <= 20
        and line.isascii()
        and line.isdecimal()
    ):
        normalized["line"] = max(1, int(line))
    else:
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

    snip = untrusted_snippet
    if type(snip) is not str or not snip:
        try:
            snip = str(snip or "")
        except Exception:
            snip = ""
    safe_snippet = safe_report_snippet(
        snip,
        max_len=snippet_max_len,
        rule_id=normalized["rule_id"],
        category=normalized["category"],
    )
    normalized = redact_sensitive_value(normalized)
    normalized["snippet"] = safe_snippet

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


def safe_report_snippet(
    snippet: str,
    max_len: int = 400,
    *,
    rule_id: str = "",
    category: str = "",
) -> str:
    """Redact sensitive report evidence and bound the remaining snippet."""
    if type(snippet) is not str:
        try:
            snippet = str(snippet or "")
        except Exception:
            snippet = ""
    if not snippet:
        return ""
    normalized_rule_id = rule_id.strip().lower() if type(rule_id) is str else ""
    normalized_category = category.strip().lower() if type(category) is str else ""
    rule_segments = frozenset(
        filter(None, normalized_rule_id.replace("_", "-").split("-"))
    )
    sensitive_asset = bool(rule_segments.intersection(_SENSITIVE_ASSET_SEGMENTS))
    sensitive_asset = sensitive_asset or {"private", "key"}.issubset(rule_segments)
    sensitive_asset = sensitive_asset or {"api", "key"}.issubset(rule_segments)
    disclosure_semantics = bool(
        rule_segments.intersection(_SENSITIVE_DISCLOSURE_SEGMENTS)
    )
    if (
        normalized_category == "secrets"
        or normalized_rule_id in _SENSITIVE_RULE_IDS
        or bool(rule_segments.intersection(_SENSITIVE_RULE_SEGMENTS))
        or (sensitive_asset and disclosure_semantics)
    ):
        return _REDACTED_SENSITIVE_SNIPPET
    max_len = max(0, max_len)
    was_truncated = len(snippet) > max_len
    inspection_len = max_len + _REDACTION_LOOKAHEAD
    visible_snippet = snippet[:max_len]
    inspection_snippet = (
        snippet[:inspection_len] if len(snippet) > inspection_len else snippet
    )
    visible_snippet = visible_snippet.replace("\r\n", "\n").replace("\r", "\n")
    inspection_snippet = inspection_snippet.replace("\r\n", "\n").replace(
        "\r", "\n"
    )
    if was_truncated:
        snippet = redact_sensitive_prefix(
            inspection_snippet,
            visible_length=len(visible_snippet),
        )
    else:
        snippet = redact_sensitive_text(visible_snippet)
    snippet = snippet.strip()
    return snippet.rstrip() + ("\n...[truncated]" if was_truncated else "")


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
