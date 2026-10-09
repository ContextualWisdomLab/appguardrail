import pytest

from appguardrail_core.reports import (ReportContext, render_agency_report,
                                       render_buyer_diligence_report,
                                       render_fix_pack,
                                       render_founder_friendly_report,
                                       render_report, supported_report_types)


def sample_findings():
    return [
        {
            "rule_id": "python-requests-verify-false",
            "severity": "HIGH",
            "message": "HTTP client disables TLS certificate verification.",
            "file": "client.py",
            "line": 7,
            "snippet": "requests.get(url, verify=False)",
            "category": "misconfig",
            "context": "app-code",
            "references": (
                "CWE-295 - Improper Certificate Validation",
                "OWASP A05:2021 - Security Misconfiguration",
            ),
            "remediation": "Keep certificate verification enabled.",
            "verification": "Rerun AppGuardrail and unit tests.",
        },
        {
            "rule_id": "docs-hardcoded-demo-secret",
            "severity": "CRITICAL",
            "message": "Demo secret in docs.",
            "file": "docs/example.md",
            "line": 3,
            "snippet": "[REDACTED: sensitive match suppressed]",
            "category": "secrets",
            "context": "doc",
            "references": ("CWE-798 - Use of Hard-coded Credentials",),
        },
    ]


def test_render_buyer_diligence_report_groups_findings_by_risk():
    context = ReportContext(
        app_name="Demo SaaS",
        repository="ContextualWisdomLab/demo",
        commit="abc123",
        generated_at="2026-07-02T00:00:00Z",
    )

    report = render_buyer_diligence_report(sample_findings(), context)

    assert "# AppGuardrail Buyer Diligence Report" in report
    assert "**App:** Demo SaaS" in report
    assert (
        "**Launch posture:** Conditional; resolve high findings before launch" in report
    )
    assert "**Deploy-blocking findings:** 1" in report
    assert "| Critical | 1 |" in report
    assert "| High | 1 |" in report
    assert "BD-001" in report
    assert "CWE-295 - Improper Certificate Validation" in report
    assert "Keep certificate verification enabled." in report
    assert "[REDACTED: sensitive match suppressed]" in report


def test_render_buyer_diligence_report_truncates_long_snippets():
    report = render_buyer_diligence_report(
        [
            {
                "rule_id": "long-snippet",
                "severity": "INFO",
                "message": "Long evidence.",
                "file": "app.py",
                "line": 1,
                "snippet": "x" * 500,
            }
        ],
        ReportContext(generated_at="2026-07-02T00:00:00Z"),
    )

    assert "...[truncated]" in report
    assert "x" * 450 not in report


def test_render_report_does_not_reemit_imported_secret_snippet():
    synthetic_secret = "synthetic-secret-value-for-regression-only"

    report = render_buyer_diligence_report(
        [
            {
                "rule_id": "external-finding-42",
                "severity": "CRITICAL",
                "category": "secrets",
                "message": "External scanner located a credential.",
                "file": "settings.py",
                "line": 4,
                "snippet": f'password="{synthetic_secret}"',
            }
        ],
        ReportContext(generated_at="2026-10-09T00:00:00Z"),
    )

    assert "[REDACTED: sensitive match suppressed]" in report
    assert synthetic_secret not in report


def test_render_report_does_not_coerce_untrusted_line_object():
    class LateSecretLine:
        def __str__(self):
            return "Authorization: ApiKey late-coercion-secret"

    report = render_buyer_diligence_report(
        [{"rule_id": "external-finding-42", "line": LateSecretLine()}],
        ReportContext(generated_at="2026-10-09T00:00:00Z"),
    )

    assert "late-coercion-secret" not in report
    assert "`n/a:1`" in report


@pytest.mark.parametrize(
    "renderer",
    (
        render_buyer_diligence_report,
        render_founder_friendly_report,
        render_agency_report,
        render_fix_pack,
    ),
)
def test_every_report_redacts_secrets_outside_snippet(renderer):
    synthetic_token = "ghp_" + "b" * 24

    report = renderer(
        [
            {
                "rule_id": "external-finding-42",
                "severity": "CRITICAL",
                "category": "misconfig",
                "message": f"Observed token={synthetic_token}",
                "remediation": f"Rotate password='{synthetic_token}'",
                "raw_evidence": synthetic_token,
            }
        ],
        ReportContext(generated_at="2026-10-09T00:00:00Z"),
    )

    assert synthetic_token not in report


def test_render_buyer_diligence_report_handles_empty_findings():
    report = render_buyer_diligence_report(
        [],
        ReportContext(
            app_name="Clean App",
            repository="ContextualWisdomLab/clean",
            generated_at="2026-07-02T00:00:00Z",
        ),
    )

    assert (
        "**Launch posture:** No deploy-blocking findings in supplied evidence" in report
    )
    assert "No findings were provided for this report." in report
    assert "No detailed findings." in report


def test_render_founder_friendly_report_creates_plain_language_fix_prompts():
    report = render_founder_friendly_report(
        sample_findings(),
        ReportContext(
            app_name="Demo SaaS",
            commit="abc123",
            generated_at="2026-07-02T00:00:00Z",
        ),
    )

    assert "# AppGuardrail Security Review Report" in report
    assert "**Overall Status:** Launch only after high-risk items are fixed" in report
    assert "## What We Checked" in report
    assert "Fix AppGuardrail finding `python-requests-verify-false`" in report
    assert "Fix `python-requests-verify-false` before launch" in report


def test_render_agency_report_groups_by_severity_and_priority():
    report = render_agency_report(
        sample_findings(),
        ReportContext(
            app_name="Demo SaaS",
            client_name="Demo Client",
            reviewer="Demo Agency",
            engagement_type="Retainer review",
            repository="ContextualWisdomLab/demo",
            commit="abc123",
            generated_at="2026-07-02T00:00:00Z",
        ),
    )

    assert "# AppGuardrail Agency Security Review Report" in report
    assert "**Client:** Demo Client" in report
    assert (
        "**Recommendation:** Approved for launch only after high findings are resolved"
        in report
    )
    assert "### High Findings" in report
    assert (
        "| AG-002 | HTTP client disables TLS certificate verifica... | High | Review | Before launch |"
        in report
    )
    assert "### Informational Findings" in report


def test_render_fix_pack_outputs_only_actionable_findings():
    report = render_fix_pack(
        [
            *sample_findings(),
            {
                "rule_id": "info-only",
                "severity": "INFO",
                "message": "Document useful context.",
                "file": "README.md",
                "line": 1,
            },
        ],
        ReportContext(
            app_name="Demo SaaS",
            generated_at="2026-07-02T00:00:00Z",
            based_on="review-123",
        ),
    )

    assert "# AppGuardrail Fix Pack" in report
    assert "**Based on review:** review-123" in report
    assert "FIX-001" in report
    assert "python-requests-verify-false" in report
    assert "info-only" not in report


def test_render_report_dispatches_supported_report_types():
    assert set(supported_report_types()) == {
        "buyer-diligence",
        "founder-friendly",
        "agency",
        "fix-pack",
    }
    report = render_report(
        "fix-pack",
        sample_findings(),
        ReportContext(generated_at="2026-07-02T00:00:00Z"),
    )

    assert "# AppGuardrail Fix Pack" in report
