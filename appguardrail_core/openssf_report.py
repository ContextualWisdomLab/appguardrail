"""Render OpenSSF Best Practices evidence in buyer-diligence reports."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable
from typing import Any


_RULE_ID = "openssf-best-practices-evidence"
_STATUS_LABELS = {
    "in_progress": "In progress",
    "passing": "Passing",
    "silver": "Silver",
    "gold": "Gold",
    "unavailable": "Unavailable",
    "malformed": "Malformed response",
    "permission_limited": "Permission limited",
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
        or parsed.hostname != "www.bestpractices.dev"
        or parsed.username is not None
        or parsed.password is not None
        or not _PROJECT_PATH_RE.fullmatch(parsed.path)
        or parsed.query
        or parsed.fragment
    ):
        return ""
    return candidate


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
        status_label = _STATUS_LABELS.get(status, "Malformed response")
        raw_tier = str(finding.get("badge_tier") or "")
        tier_label = raw_tier.replace("_", " ").title() if raw_tier else "Not verified"
        verified_at = _table_text(finding.get("verified_at") or "Not reported")
        repository = _table_text(finding.get("repository_url") or "Not reported")
        project_url = _safe_project_url(finding.get("evidence_url"))
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
            "",
        ]
    )
    return lines
