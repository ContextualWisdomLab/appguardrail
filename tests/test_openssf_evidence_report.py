"""Buyer-diligence report contracts for OpenSSF Best Practices evidence."""

from __future__ import annotations

from appguardrail_core.reports import (
    ReportContext,
    render_buyer_diligence_report,
    render_report,
)


GENERATED_AT = "2026-08-04T08:00:00Z"


def _finding(
    repository: str = "https://github.com/acme/project",
    status: str = "gold",
    tier: str = "gold",
    evidence_url: str = "https://www.bestpractices.dev/projects/42",
) -> dict[str, object]:
    """Return one normalized-evidence-shaped finding for report tests."""
    return {
        "rule_id": "openssf-best-practices-evidence",
        "severity": (
            "INFO"
            if status in {"in_progress", "passing", "silver", "gold"}
            else "WARNING"
        ),
        "message": "OpenSSF evidence state.",
        "file": "OpenSSF Best Practices API",
        "line": 1,
        "category": "supply-chain",
        "context": "governance",
        "remediation": "Verify evidence.",
        "verification": "Repeat the exact repository URL lookup.",
        "references": ["https://www.bestpractices.dev"],
        "evidence_status": status,
        "badge_tier": tier,
        "evidence_url": evidence_url,
        "verified_at": GENERATED_AT,
        "project_id": 42 if tier else None,
        "tiered_percentage": 300 if tier == "gold" else None,
        "repository_url": repository,
        "source_origin": "https://www.bestpractices.dev",
        "evidence_reason": "" if tier else "no_matching_public_project",
    }


def _report(findings: list[dict[str, object]]) -> str:
    """Render a deterministic buyer-diligence report."""
    return render_buyer_diligence_report(
        findings,
        ReportContext(generated_at=GENERATED_AT),
    )


def test_report_renders_dedicated_openssf_evidence_table() -> None:
    """Buyer diligence must surface tier, timestamp, repository, and evidence link."""
    report = _report([_finding()])

    assert "## OpenSSF Best Practices Evidence" in report
    assert report.index("## OpenSSF Best Practices Evidence") < report.index(
        "## Findings Summary"
    )
    assert (
        "| Repository | Verification status | Badge tier | Verified | Evidence |"
        in report
    )
    assert (
        "| `https://github.com/acme/project` | Gold | Gold | "
        "2026-08-04T08:00:00Z | "
        "[Project evidence](https://www.bestpractices.dev/projects/42) |"
        in report
    )
    assert (
        "Source attribution: OpenSSF Best Practices badge contributors "
        "(CC-BY-3.0+)."
        in report
    )


def test_existing_report_dispatcher_uses_the_augmented_buyer_renderer() -> None:
    """The established `appguardrail report buyer-diligence` path gains evidence."""
    report = render_report(
        "buyer-diligence",
        [_finding(status="silver", tier="silver")],
        ReportContext(generated_at=GENERATED_AT),
    )

    assert "## OpenSSF Best Practices Evidence" in report
    assert "| `https://github.com/acme/project` | Silver | Silver |" in report


def test_report_distinguishes_non_affirmative_evidence_states() -> None:
    """Unavailable, malformed, and permission-limited states must not become badge claims."""
    report = _report(
        [
            _finding("https://github.com/acme/a", "unavailable", "", ""),
            _finding("https://github.com/acme/b", "malformed", "", ""),
            _finding("https://github.com/acme/c", "permission_limited", "", ""),
            _finding("https://github.com/acme/d", "in_progress", "in_progress"),
        ]
    )

    assert "| `https://github.com/acme/a` | Unavailable | Not verified |" in report
    assert "| `https://github.com/acme/b` | Malformed response | Not verified |" in report
    assert "| `https://github.com/acme/c` | Permission limited | Not verified |" in report
    assert "| `https://github.com/acme/d` | In progress | In progress |" in report
    assert (
        "Unavailable means no matching public evidence was observed at "
        "verification time; it does not prove non-registration."
        in report
    )


def test_report_states_when_no_openssf_record_was_supplied() -> None:
    """Absence from input must be described as missing supplied evidence, not failure."""
    report = _report([])

    assert "## OpenSSF Best Practices Evidence" in report
    assert (
        "No OpenSSF Best Practices evidence record was supplied for this report."
        in report
    )
    assert "not registered" not in report.lower()


def test_report_sorts_repositories_and_neutralizes_table_injection() -> None:
    """Externally supplied metadata must not break Markdown tables or inject HTML links."""
    hostile = _finding(
        "https://github.com/zeta/project|<script>alert(1)</script>",
        "gold",
        "gold|fake",
        "javascript:alert(1)",
    )
    alpha = _finding("https://github.com/alpha/project", "passing", "passing")

    report = _report([hostile, alpha])

    assert report.index("`https://github.com/alpha/project`") < report.index(
        "`https://github.com/zeta/project"
    )
    assert "project\\|&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "Gold\\|fake" in report
    assert "javascript:alert(1)" not in report
    assert (
        "Project evidence"
        not in report.split("https://github.com/zeta/project", 1)[1].splitlines()[0]
    )


def test_non_evidence_findings_do_not_create_evidence_rows() -> None:
    """Ordinary security findings remain in their existing sections only."""
    ordinary = {
        "rule_id": "dangerous-eval",
        "severity": "HIGH",
        "message": "eval used",
        "file": "app.py",
        "line": 4,
        "category": "injection",
        "context": "app-code",
    }

    report = _report([ordinary])

    evidence_section = report.split("## OpenSSF Best Practices Evidence", 1)[1].split(
        "## Findings Summary", 1
    )[0]
    assert "No OpenSSF Best Practices evidence record was supplied" in evidence_section
    assert "dangerous-eval" not in evidence_section
