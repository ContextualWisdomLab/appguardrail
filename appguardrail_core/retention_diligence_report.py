"""Compose non-secret retention evidence into buyer-diligence reports.

This module deliberately extends the existing report renderer instead of
expanding :class:`appguardrail_core.reports.ReportContext` with tenant-specific
state. Keeping evidence as an explicit argument prevents accidental reuse in
other report types and makes missing posture visible rather than silently
implying that retention controls were verified.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from appguardrail_core.reports import (
    ReportContext,
    _md_prose,
    render_buyer_diligence_report,
)
from appguardrail_core.retention_diligence import RetentionAuditPosture

_MARKDOWN_LINK_TARGET = re.compile(r"(?<=\\\])\(([^)\n]*)\)")


def _markdown_literal(value: Any) -> str:
    """Return arbitrary identifier text without active HTML or Markdown markup.

    Buyer evidence identifiers are bounded but may legitimately contain markup
    metacharacters. HTML is neutralized with the report renderer's canonical
    prose helper, then Markdown backslashes, code spans, bracket links, and
    simple inline-link targets are escaped while ordinary identifier text stays
    readable.
    """
    safe = _md_prose(value)
    safe = safe.replace("\\", "\\\\")
    safe = safe.replace("`", "\\`").replace("[", "\\[").replace("]", "\\]")
    return _MARKDOWN_LINK_TARGET.sub(r"\\(\1\\)", safe)


def render_buyer_retention_diligence_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
    *,
    retention_audit_posture: RetentionAuditPosture | None = None,
) -> str:
    """Render buyer diligence plus an explicit retention/audit evidence section.

    The base security-finding report remains the canonical renderer. Retention
    evidence is appended as a separate bounded section so callers must provide
    it intentionally. A missing posture is rendered as ``Not supplied`` rather
    than being interpreted as verified or compliant.
    """
    base_report = render_buyer_diligence_report(findings, context).rstrip()
    section = render_retention_audit_posture(retention_audit_posture)
    return f"{base_report}\n\n{section}\n"


def render_retention_audit_posture(
    posture: RetentionAuditPosture | None,
) -> str:
    """Render one non-secret, decision-oriented retention evidence section."""
    lines = ["## Retention And Audit Posture", ""]
    if posture is None:
        lines.extend(
            [
                "- Evidence status: Not supplied",
                "- Next action: supply a current tenant retention/audit posture snapshot before relying on deletion or audit claims.",
            ]
        )
        return "\n".join(lines)

    evidence = posture.to_dict()
    status = str(evidence["evidence_status"]).title()
    audit_chain = evidence["audit_chain"]
    retention_days = evidence["retention_days"]
    last_purge = evidence["last_purge"]

    lines.extend(
        [
            f"- Evidence status: {status}",
            f"- Policy revision: {evidence['policy_revision']}",
            "- Retention windows: "
            + ", ".join(
                f"{category}={days} days"
                for category, days in retention_days.items()
            ),
            f"- Active legal holds: {evidence['legal_hold_count']}",
            "- Audit chain: "
            f"{str(audit_chain['status']).title()} ({audit_chain['event_count']} events)",
            f"- Audit head hash: {audit_chain['head_hash']}",
            f"- Evidence verified at: {evidence['verified_at']}",
        ]
    )
    if last_purge is None:
        lines.append("- Last purge: No completed purge receipt supplied")
    else:
        lines.append(
            "- Last purge: "
            f"{_markdown_literal(last_purge['receipt_id'])} at {last_purge['executed_at']} "
            f"(policy revision {last_purge['policy_revision']}, "
            f"legal-hold revision {last_purge['legal_hold_revision']})"
        )

    if posture.evidence_status == "verified":
        lines.append(
            "- Next action: re-verify this posture against the current tenant state before acquisition reliance."
        )
    else:
        lines.append(
            "- Next action: investigate the incomplete audit-chain evidence and re-verify it before relying on retention or deletion claims."
        )
    return "\n".join(lines)
