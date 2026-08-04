"""Render OpenSSF Best Practices evidence in buyer-diligence reports."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable
from typing import Any

from appguardrail_core.openssf_evidence import (
    ATTRIBUTION,
    CONTENT_LICENSE,
    CURRENT_ORIGIN,
)


_RULE_ID = "openssf-best-practices-evidence"
_FINDINGS_SUMMARY_MARKER = "## Findings Summary"
_STATUS_LABELS = {
    "in_progress": "In progress",
    "passing": "Passing",
    "silver": "Silver",
    "gold": "Gold",
    "unavailable": "Unavailable",
    "malformed": "Malformed response",
    "permission_limited": "Permission limited",
}
_BADGE_TIER_LABELS = {
    status: _STATUS_LABELS[status]
    for status in ("in_progress", "passing", "silver", "gold")
}
_PROJECT_PATH_RE = re.compile(r"^/projects/[1-9][0-9]*$", re.IGNORECASE)


def _table_text(value: Any) -> str:
    """Neutralize external text for one Markdown table cell or code span."""
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _safe_project_url(value: Any) -> str:
    """Return one canonical public project URL, otherwise an empty string."""
    candidate = str(value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return ""
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != "www.bestpractices.dev"
        or parsed.username is not None
        or parsed.password is not None
        or not _PROJECT_PATH_RE.fullmatch(parsed.path)
        or parsed.query
        or parsed.fragment
    ):
        return ""
    return candidate


def _affirmative_metadata_is_consistent(
    finding: dict[str, Any], status: str, raw_tier: str
) -> bool:
    """Return whether an affirmative row has one canonical project identity."""
    project_id = finding.get("project_id")
    if (
        raw_tier != status
        or not isinstance(project_id, int)
        or isinstance(project_id, bool)
        or project_id <= 0
    ):
        return False
    expected_url = f"{CURRENT_ORIGIN}/projects/{project_id}"
    return _safe_project_url(finding.get("evidence_url")) == expected_url


def _non_affirmative_metadata_is_consistent(
    finding: dict[str, Any], raw_tier: str
) -> bool:
    """Return whether a non-affirmative row carries no stale badge assertion."""
    return (
        not raw_tier
        and not finding.get("evidence_url")
        and finding.get("project_id") is None
        and finding.get("tiered_percentage") is None
    )


def render_openssf_evidence_section(
    findings: Iterable[dict[str, Any]],
) -> list[str]:
    """Render a stable evidence table without turning absence into a badge claim."""
    evidence = [
        finding
        for finding in findings
        if str(finding.get("rule_id") or "") == _RULE_ID
    ]
    lines = ["## OpenSSF Best Practices Evidence", ""]
    if not evidence:
        lines.extend(
            [
                "No OpenSSF Best Practices evidence record was supplied for this report.",
                "",
            ]
        )
        return lines

    lines.extend(
        [
            "| Repository | Verification status | Badge tier | Verified | Evidence |",
            "|---|---|---|---|---|",
        ]
    )
    evidence.sort(key=lambda item: _table_text(item.get("repository_url")).casefold())
    for finding in evidence:
        status = str(finding.get("evidence_status") or "malformed")
        raw_tier = str(finding.get("badge_tier") or "")
        affirmative = status in _BADGE_TIER_LABELS
        metadata_consistent = (
            _affirmative_metadata_is_consistent(finding, status, raw_tier)
            if affirmative
            else _non_affirmative_metadata_is_consistent(finding, raw_tier)
        )
        if metadata_consistent:
            status_label = _STATUS_LABELS.get(status, "Malformed response")
            tier_label = _BADGE_TIER_LABELS.get(raw_tier, "Not verified")
            project_url = (
                _safe_project_url(finding.get("evidence_url")) if affirmative else ""
            )
        else:
            status_label = "Malformed response"
            tier_label = "Not verified"
            project_url = ""
        verified_at = _table_text(finding.get("verified_at") or "Not reported")
        repository = _table_text(finding.get("repository_url") or "Not reported")
        link = f"[Project evidence]({project_url})" if project_url else "Not available"
        lines.append(
            "| `{repository}` | {status} | {tier} | {verified} | {link} |".format(
                repository=repository,
                status=_table_text(status_label),
                tier=_table_text(tier_label),
                verified=verified_at,
                link=link,
            )
        )
    lines.extend(
        [
            "",
            "Unavailable means no matching public evidence was observed at verification time; it does not prove non-registration.",
            f"Source attribution: {ATTRIBUTION}. License policy: {CONTENT_LICENSE}.",
            "",
        ]
    )
    return lines


def augment_buyer_diligence_report(
    rendered_report: str,
    findings: Iterable[dict[str, Any]],
) -> str:
    """Insert the evidence section before the existing findings summary heading."""
    if rendered_report.count(_FINDINGS_SUMMARY_MARKER) != 1:
        raise ValueError("buyer-diligence report must contain one findings summary")
    section = "\n".join(render_openssf_evidence_section(findings))
    return rendered_report.replace(
        _FINDINGS_SUMMARY_MARKER,
        section + _FINDINGS_SUMMARY_MARKER,
        1,
    )
