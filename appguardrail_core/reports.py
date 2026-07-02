"""Report builders backed by normalized AppGuardrail findings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterable

from appguardrail_core.findings import (
    SEVERITIES,
    finding_sort_key,
    is_deploy_blocking,
    normalize_finding,
    severity_counts,
)


@dataclass(frozen=True)
class ReportContext:
    """Context shown in generated diligence reports."""

    app_name: str = "AppGuardrail scan target"
    repository: str = "n/a"
    commit: str = "n/a"
    generated_at: str = ""
    scan_command: str = "appguardrail scan ."
    scope: str = "Application source, configuration, and security workflow evidence."


def render_buyer_diligence_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render a buyer-diligence markdown report from normalized findings."""
    context = context or ReportContext()
    normalized = [normalize_finding(finding) for finding in findings]
    normalized.sort(key=finding_sort_key)
    counts = severity_counts(normalized)
    blockers = [finding for finding in normalized if is_deploy_blocking(finding)]

    generated_at = context.generated_at or datetime.now(UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    lines = [
        "# AppGuardrail Buyer Diligence Report",
        "",
        f"**App:** {context.app_name}",
        f"**Repository:** {context.repository}",
        f"**Commit:** {context.commit}",
        f"**Generated:** {generated_at}",
        f"**Scan command:** `{context.scan_command}`",
        "",
        "## Executive Readout",
        "",
        f"**Launch posture:** {_launch_posture(blockers)}",
        f"**Deploy-blocking findings:** {len(blockers)}",
        "",
        "| Severity | Count |",
        "|---|---:|",
        *[f"| {severity.title()} | {counts[severity]} |" for severity in SEVERITIES],
        "",
        "## Scope And Evidence Handling",
        "",
        f"- Scope: {context.scope}",
        "- Raw customer code, secrets, tokens, and authorization values are not included.",
        "- Findings are grouped by public security taxonomy where available.",
        "- Suggested remediation is generated from AppGuardrail normalized metadata.",
        "",
        "## Findings Summary",
        "",
    ]

    if normalized:
        lines.extend(_summary_table(normalized))
    else:
        lines.append("No findings were provided for this report.")

    lines.extend(["", "## Detailed Findings", ""])
    if normalized:
        for index, finding in enumerate(normalized, start=1):
            lines.extend(_finding_detail(index, finding))
    else:
        lines.append("No detailed findings.")

    lines.extend(
        [
            "",
            "## Buyer Follow-Up Checklist",
            "",
            "- Confirm critical and high app-code findings are fixed or formally accepted.",
            "- Re-run AppGuardrail and external engines used in the sale-readiness plan.",
            "- Preserve GitHub Actions links and issue history for audit evidence.",
            "- Confirm privacy retention, redaction policy, and authorized DAST targets.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _launch_posture(blockers: list[dict[str, Any]]) -> str:
    if any(finding["severity"] == "CRITICAL" for finding in blockers):
        return "Hold pending critical remediation"
    if blockers:
        return "Conditional; resolve high findings before launch"
    return "No deploy-blocking findings in supplied evidence"


def _summary_table(findings: list[dict[str, Any]]) -> list[str]:
    rows = [
        "| ID | Severity | Category | Location | References |",
        "|---|---|---|---|---|",
    ]
    for index, finding in enumerate(findings, start=1):
        references = ", ".join(finding["references"] or finding["owasp"] or finding["cwe"])
        rows.append(
            "| {id} | {severity} | {category} | `{location}` | {references} |".format(
                id=f"BD-{index:03d}",
                severity=finding["severity"].title(),
                category=finding["category"],
                location=f"{finding['file']}:{finding['line']}",
                references=references or "n/a",
            )
        )
    return rows


def _finding_detail(index: int, finding: dict[str, Any]) -> list[str]:
    references = ", ".join(finding["references"] or finding["owasp"] or finding["cwe"])
    return [
        f"### BD-{index:03d}: {_short_title(finding['message'])}",
        "",
        f"- Severity: {finding['severity'].title()}",
        f"- Rule: `{finding['rule_id']}`",
        f"- Category: `{finding['category']}`",
        f"- Context: `{finding['context']}`",
        f"- Location: `{finding['file']}:{finding['line']}`",
        f"- References: {references or 'n/a'}",
        "",
        "**Evidence:**",
        "",
        f"```text\n{finding['snippet'] or '(snippet unavailable)'}\n```",
        "",
        f"**Risk:** {finding['message']}",
        "",
        f"**Remediation:** {finding['remediation']}",
        "",
        f"**Verification:** {finding['verification']}",
        "",
    ]


def _short_title(message: str, max_len: int = 84) -> str:
    title = message.split(".", 1)[0].strip() or "Security finding"
    if len(title) <= max_len:
        return title
    return title[: max_len - 3].rstrip() + "..."
