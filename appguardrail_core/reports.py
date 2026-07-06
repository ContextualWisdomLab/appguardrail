"""Report builders backed by normalized AppGuardrail findings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
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
    client_name: str = "n/a"
    reviewer: str = "AppGuardrail"
    engagement_type: str = "Pre-launch review"
    based_on: str = "AppGuardrail findings JSON"


REPORT_TYPE_LABELS = {
    "buyer-diligence": "Buyer diligence report",
    "founder-friendly": "Founder-friendly report",
    "agency": "Agency report",
    "fix-pack": "Fix pack",
}


def supported_report_types() -> tuple[str, ...]:
    """Return CLI-visible report types."""
    return tuple(REPORT_TYPE_LABELS)


def render_report(
    report_type: str,
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render any supported report type from normalized findings."""
    renderers = {
        "buyer-diligence": render_buyer_diligence_report,
        "founder-friendly": render_founder_friendly_report,
        "agency": render_agency_report,
        "fix-pack": render_fix_pack,
    }
    try:
        renderer = renderers[report_type]
    except KeyError as exc:
        raise ValueError(f"Unsupported report type: {report_type}") from exc
    return renderer(findings, context)


_HTML_STYLE = """\
:root { color-scheme: light dark; }
body {
  margin: 0;
  padding: 2rem 1rem;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  line-height: 1.6;
  color: #1f2933;
  background: #f5f7fa;
}
main {
  max-width: 56rem;
  margin: 0 auto;
  padding: 2.5rem 3rem;
  background: #ffffff;
  border: 1px solid #d9e2ec;
  border-radius: 8px;
}
h1 { font-size: 1.7rem; border-bottom: 2px solid #d9e2ec; padding-bottom: 0.4rem; }
h2 { font-size: 1.3rem; margin-top: 2rem; border-bottom: 1px solid #e4eaf1; padding-bottom: 0.25rem; }
h3 { font-size: 1.1rem; margin-top: 1.5rem; }
h4 { font-size: 1rem; margin-top: 1.25rem; }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.9em;
  background: #eef2f6;
  border-radius: 3px;
  padding: 0.1em 0.35em;
}
pre {
  background: #f0f4f8;
  border: 1px solid #d9e2ec;
  border-radius: 6px;
  padding: 0.75rem 1rem;
  overflow-x: auto;
}
pre code { background: none; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 0.75rem 0; }
th, td { border: 1px solid #d9e2ec; padding: 0.4rem 0.6rem; text-align: left; }
th { background: #f0f4f8; }
ul, ol { padding-left: 1.5rem; }
@media (prefers-color-scheme: dark) {
  body { color: #e4eaf1; background: #10161d; }
  main { background: #171f28; border-color: #2c3a49; }
  h1, h2 { border-color: #2c3a49; }
  code { background: #22303f; }
  pre { background: #10161d; border-color: #2c3a49; }
  th, td { border-color: #2c3a49; }
  th { background: #22303f; }
}
"""

_TABLE_SEPARATOR_CELL = re.compile(r":?-{3,}:?")


def render_html(
    report_type: str,
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render any supported report type as a self-contained HTML document.

    Wraps the existing markdown renderers, converting their bounded markdown
    dialect (headings, bold, inline code, fences, tables, lists, paragraphs)
    with all text HTML-escaped, so reports are safe to open and share as-is.
    """
    markdown = render_report(report_type, findings, context)
    title = f"AppGuardrail — {REPORT_TYPE_LABELS[report_type]}"
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{escape(title)}</title>\n"
        f"<style>\n{_HTML_STYLE}</style>\n"
        "</head>\n"
        "<body>\n"
        "<main>\n"
        f"{_markdown_to_html(markdown)}\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )


def _inline_html(text: str) -> str:
    """HTML-escape text, then apply bold and inline-code markdown spans."""
    escaped = escape(text)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    return escaped


def _table_html(rows: list[str]) -> str:
    """Convert consecutive markdown table rows into an HTML table."""
    parsed: list[list[str]] = []
    for row in rows:
        cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
        if cells and all(_TABLE_SEPARATOR_CELL.fullmatch(cell) for cell in cells):
            continue
        parsed.append(cells)
    if not parsed:
        return ""
    lines = ["<table>"]
    for row_index, cells in enumerate(parsed):
        tag = "th" if row_index == 0 else "td"
        rendered = "".join(f"<{tag}>{_inline_html(cell)}</{tag}>" for cell in cells)
        lines.append(f"<tr>{rendered}</tr>")
    lines.append("</table>")
    return "\n".join(lines)


def _markdown_to_html(markdown: str) -> str:
    """Convert the bounded markdown dialect used by report renderers to HTML."""
    lines = markdown.splitlines()
    out: list[str] = []
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        if paragraph:
            out.append("<p>" + " ".join(_inline_html(part) for part in paragraph) + "</p>")
            paragraph.clear()

    index = 0
    total = len(lines)
    while index < total:
        stripped = lines[index].strip()

        if stripped.startswith("```"):
            flush_paragraph()
            index += 1
            code_lines = []
            while index < total and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            index += 1  # Skip the closing fence.
            out.append("<pre><code>" + escape("\n".join(code_lines)) + "</code></pre>")
            continue

        if not stripped:
            flush_paragraph()
            index += 1
            continue

        heading = re.fullmatch(r"(#{1,4})\s+(.*)", stripped)
        if heading:
            flush_paragraph()
            level = len(heading.group(1))
            out.append(f"<h{level}>{_inline_html(heading.group(2))}</h{level}>")
            index += 1
            continue

        if stripped.startswith("|"):
            flush_paragraph()
            table_rows = []
            while index < total and lines[index].strip().startswith("|"):
                table_rows.append(lines[index].strip())
                index += 1
            out.append(_table_html(table_rows))
            continue

        if stripped.startswith("- "):
            flush_paragraph()
            items = []
            while index < total and lines[index].strip().startswith("- "):
                items.append(lines[index].strip()[2:])
                index += 1
            out.append(
                "<ul>"
                + "".join(f"<li>{_inline_html(item)}</li>" for item in items)
                + "</ul>"
            )
            continue

        if re.match(r"\d+\.\s+", stripped):
            flush_paragraph()
            items = []
            while index < total:
                ordered = re.fullmatch(r"\d+\.\s+(.*)", lines[index].strip())
                if not ordered:
                    break
                items.append(ordered.group(1))
                index += 1
            out.append(
                "<ol>"
                + "".join(f"<li>{_inline_html(item)}</li>" for item in items)
                + "</ol>"
            )
            continue

        paragraph.append(stripped)
        index += 1

    flush_paragraph()
    return "\n".join(part for part in out if part)


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


def render_founder_friendly_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render a plain-language launch readiness report for founders."""
    context, normalized, counts, blockers, generated_at = _prepare_report(
        findings, context
    )
    lines = [
        "# AppGuardrail Security Review Report",
        "",
        f"**App:** {context.app_name}",
        f"**Reviewed by:** {context.reviewer}",
        f"**Date:** {generated_at}",
        f"**Version / Commit:** {context.commit}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
        *[f"| {severity.title()} | {counts[severity]} |" for severity in SEVERITIES],
        "",
        f"**Overall Status:** {_founder_status(blockers)}",
        "",
        "## What We Checked",
        "",
        "- Authentication and protected routes",
        "- Authorization and ownership checks",
        "- Secrets and environment variables",
        "- Database security and query construction",
        "- File uploads and user-controlled paths",
        "- Payments, webhooks, CORS, headers, and deployment configuration",
        "",
        "## Findings",
        "",
    ]
    if normalized:
        for index, finding in enumerate(normalized, start=1):
            lines.extend(_founder_finding(index, finding))
    else:
        lines.append("No findings were provided for this report.")

    lines.extend(
        [
            "",
            "## What's Good",
            "",
            "- AppGuardrail evidence is normalized for repeatable review.",
            "- Report snippets are trimmed to avoid carrying raw secrets or oversized logs.",
            "- Public taxonomy references are included when findings provide them.",
            "",
            "## Recommended Next Steps",
            "",
        ]
    )
    lines.extend(_next_steps(normalized, blockers))
    lines.extend(
        [
            "",
            "## Scope And Limitations",
            "",
            f"- Scope: {context.scope}",
            "- This report summarizes supplied AppGuardrail findings and does not replace a full penetration test.",
            "- Third-party service internals and social engineering are outside this report unless separately reviewed.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_agency_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render a client-ready agency security review report."""
    context, normalized, counts, blockers, generated_at = _prepare_report(
        findings, context
    )
    lines = [
        "# AppGuardrail Agency Security Review Report",
        "",
        f"**Client:** {context.client_name}",
        f"**Project:** {context.app_name}",
        f"**Reviewed by:** {context.reviewer}",
        f"**Date:** {generated_at}",
        f"**Engagement type:** {context.engagement_type}",
        "",
        "## Executive Summary",
        "",
        f"**Critical findings requiring immediate action:** {counts['CRITICAL']}",
        f"**High-severity findings:** {counts['HIGH']}",
        f"**Total findings:** {len(normalized)}",
        f"**Recommendation:** {_agency_recommendation(blockers)}",
        "",
        "## Methodology",
        "",
        "1. Static analysis of source, config, and workflow evidence.",
        "2. External engine ingestion when Bandit, Ruff, Semgrep, Trivy, or ZAP findings are supplied.",
        "3. Normalization to AppGuardrail severity, context, remediation, and verification metadata.",
        "4. Client-ready prioritization by deploy-blocking risk.",
        "",
        "## Findings",
        "",
    ]
    if normalized:
        for severity in SEVERITIES:
            severity_findings = [
                finding for finding in normalized if finding["severity"] == severity
            ]
            lines.extend(_agency_severity_section(severity, severity_findings))
    else:
        lines.append("No findings were provided for this report.")

    lines.extend(
        [
            "",
            "## Remediation Priority Matrix",
            "",
        ]
    )
    if normalized:
        lines.extend(_priority_matrix(normalized))
    else:
        lines.append("No remediation items.")

    lines.extend(
        [
            "",
            "## Retest Notes",
            "",
            "| ID | Status | Notes |",
            "|---|---|---|",
        ]
    )
    if normalized:
        for index, finding in enumerate(normalized, start=1):
            lines.append(f"| AG-{index:03d} | Pending | Rerun {finding['rule_id']} evidence. |")
    else:
        lines.append("| n/a | n/a | No findings. |")

    lines.extend(
        [
            "",
            "## Appendix A: Tools Used",
            "",
            f"- `{context.scan_command}`",
            "- AppGuardrail normalized findings contract",
            "",
            "## Appendix B: Scope",
            "",
            f"- Repository: {context.repository}",
            f"- Commit: {context.commit}",
            f"- Scope: {context.scope}",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_fix_pack(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render AI-ready remediation prompts and verification steps."""
    context, normalized, _counts, _blockers, generated_at = _prepare_report(
        findings, context
    )
    actionable = [
        finding
        for finding in normalized
        if finding["severity"] in {"CRITICAL", "HIGH", "WARNING"}
    ]
    lines = [
        "# AppGuardrail Fix Pack",
        "",
        "A Fix Pack turns AppGuardrail findings into AI-ready remediation work items.",
        "",
        f"**App:** {context.app_name}",
        f"**Fix Pack generated:** {generated_at}",
        f"**Based on review:** {context.based_on}",
        "",
        "## How To Use This Fix Pack",
        "",
        "1. Work through each item from top to bottom: Critical, High, then Warning.",
        "2. Copy the Fix Prompt into Claude Code, Cursor, Codex, or another coding assistant.",
        "3. Apply the change in a branch, then run the Verification Test.",
        "4. Re-run AppGuardrail before marking the item fixed.",
        "",
        "## Fix Items",
        "",
    ]
    if actionable:
        for index, finding in enumerate(actionable, start=1):
            lines.extend(_fix_item(index, finding))
    else:
        lines.append("No critical, high, or warning findings were provided.")

    lines.extend(
        [
            "",
            "## Fix Pack Status",
            "",
        ]
    )
    if actionable:
        lines.extend(_fix_status_table(actionable))
    else:
        lines.append("No open fix items.")

    lines.extend(
        [
            "",
            "## Post-Fix Checklist",
            "",
            "- Run `appguardrail scan .` and confirm no new deploy-blocking issues.",
            "- Run the project test suite and confirm no regressions.",
            "- Deploy to staging and repeat the listed verification tests.",
            "- Keep the report and scan JSON as remediation evidence.",
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


def _prepare_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None,
) -> tuple[
    ReportContext,
    list[dict[str, Any]],
    dict[str, int],
    list[dict[str, Any]],
    str,
]:
    context = context or ReportContext()
    normalized = [normalize_finding(finding) for finding in findings]
    normalized.sort(key=finding_sort_key)
    counts = severity_counts(normalized)
    blockers = [finding for finding in normalized if is_deploy_blocking(finding)]
    generated_at = context.generated_at or datetime.now(UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return context, normalized, counts, blockers, generated_at


def _founder_status(blockers: list[dict[str, Any]]) -> str:
    if any(finding["severity"] == "CRITICAL" for finding in blockers):
        return "Not ready for public launch"
    if blockers:
        return "Launch only after high-risk items are fixed"
    return "Cleared for launch based on supplied findings"


def _founder_finding(index: int, finding: dict[str, Any]) -> list[str]:
    return [
        f"### Finding {index}: {_short_title(finding['message'])}",
        "",
        f"**Severity:** {finding['severity'].title()}",
        "",
        f"**What we found:** {finding['message']}",
        "",
        f"**Why it matters:** {_plain_risk(finding)}",
        "",
        "**Fix prompt:**",
        "",
        f"```text\n{_fix_prompt(finding)}\n```",
        "",
        f"**How to verify the fix:** {finding['verification']}",
        "",
    ]


def _plain_risk(finding: dict[str, Any]) -> str:
    severity = finding["severity"]
    if severity == "CRITICAL":
        return "This can expose sensitive data, credentials, money movement, or remote execution risk if reachable in production."
    if severity == "HIGH":
        return "This is likely to become a launch blocker if the affected code is reachable by users or automated workflows."
    if severity == "WARNING":
        return "This may be safe in context, but it needs a deliberate review before launch."
    return "This is useful context for hardening and buyer diligence."


def _fix_prompt(finding: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"Fix AppGuardrail finding `{finding['rule_id']}` in `{finding['file']}:{finding['line']}`.",
            "",
            f"Problem: {finding['message']}",
            f"Recommended remediation: {finding['remediation']}",
            "",
            f"After applying the fix, verify with: {finding['verification']}",
        ]
    )


def _next_steps(
    findings: list[dict[str, Any]], blockers: list[dict[str, Any]]
) -> list[str]:
    if not findings:
        return ["1. Re-run AppGuardrail with current production-bound code."]
    steps = []
    if blockers:
        first = blockers[0]
        steps.append(
            f"1. Fix `{first['rule_id']}` before launch because it is deploy-blocking."
        )
        steps.append("2. Re-run AppGuardrail and keep the findings JSON as evidence.")
        steps.append("3. Review warning and info items before the next release.")
    else:
        steps.append("1. Keep this clean findings snapshot with release evidence.")
        steps.append("2. Re-run AppGuardrail on every security-sensitive pull request.")
        steps.append("3. Schedule periodic external engine checks for drift.")
    return steps


def _agency_recommendation(blockers: list[dict[str, Any]]) -> str:
    if any(finding["severity"] == "CRITICAL" for finding in blockers):
        return "Hold pending critical fixes"
    if blockers:
        return "Approved for launch only after high findings are resolved"
    return "Cleared based on supplied AppGuardrail evidence"


def _agency_severity_section(
    severity: str, findings: list[dict[str, Any]]
) -> list[str]:
    heading = severity.title() if severity != "INFO" else "Informational"
    lines = [f"### {heading} Findings", ""]
    if not findings:
        lines.append(f"No {heading.lower()} findings.")
        lines.append("")
        return lines
    for finding in findings:
        lines.extend(
            [
                f"#### {_short_title(finding['message'])}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Severity | {finding['severity'].title()} |",
                f"| Category | `{finding['category']}` |",
                f"| Affected Component | `{finding['file']}:{finding['line']}` |",
                f"| Rule | `{finding['rule_id']}` |",
                f"| References | {_references(finding)} |",
                "",
                f"**Description:** {finding['message']}",
                "",
                f"**Remediation:** {finding['remediation']}",
                "",
                f"**Verification:** {finding['verification']}",
                "",
            ]
        )
    return lines


def _priority_matrix(findings: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| ID | Title | Severity | Effort | Priority |",
        "|---|---|---|---|---|",
    ]
    for index, finding in enumerate(findings, start=1):
        priority = _priority_for(finding)
        lines.append(
            "| {id} | {title} | {severity} | {effort} | {priority} |".format(
                id=f"AG-{index:03d}",
                title=_short_title(finding["message"], max_len=48),
                severity=finding["severity"].title(),
                effort="Review",
                priority=priority,
            )
        )
    return lines


def _priority_for(finding: dict[str, Any]) -> str:
    if is_deploy_blocking(finding):
        return "Immediate" if finding["severity"] == "CRITICAL" else "Before launch"
    if finding["severity"] == "WARNING":
        return "Within 30 days"
    return "Backlog"


def _fix_item(index: int, finding: dict[str, Any]) -> list[str]:
    return [
        f"### [ ] FIX-{index:03d}: {_short_title(finding['message'])}",
        "",
        f"**Severity:** {finding['severity'].title()}",
        "",
        f"**Problem:** {finding['message']}",
        "",
        f"**Risk:** {_plain_risk(finding)}",
        "",
        "**Fix Prompt:**",
        "",
        f"```text\n{_fix_prompt(finding)}\n```",
        "",
        "**Verification Test:**",
        "",
        f"{finding['verification']}",
        "",
    ]


def _fix_status_table(findings: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| ID | Title | Severity | Status | Fixed By | Verified |",
        "|---|---|---|---|---|---|",
    ]
    for index, finding in enumerate(findings, start=1):
        lines.append(
            "| {id} | {title} | {severity} | Open | | |".format(
                id=f"FIX-{index:03d}",
                title=_short_title(finding["message"], max_len=48),
                severity=finding["severity"].title(),
            )
        )
    return lines


def _references(finding: dict[str, Any]) -> str:
    return ", ".join(finding["references"] or finding["owasp"] or finding["cwe"]) or "n/a"
