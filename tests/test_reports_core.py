from appguardrail_core.reports import ReportContext, render_buyer_diligence_report


def test_render_buyer_diligence_report_groups_findings_by_risk():
    findings = [
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
    context = ReportContext(
        app_name="Demo SaaS",
        repository="ContextualWisdomLab/demo",
        commit="abc123",
        generated_at="2026-07-02T00:00:00Z",
    )

    report = render_buyer_diligence_report(findings, context)

    assert "# AppGuardrail Buyer Diligence Report" in report
    assert "**App:** Demo SaaS" in report
    assert "**Launch posture:** Conditional; resolve high findings before launch" in report
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


def test_render_buyer_diligence_report_handles_empty_findings():
    report = render_buyer_diligence_report(
        [],
        ReportContext(
            app_name="Clean App",
            repository="ContextualWisdomLab/clean",
            generated_at="2026-07-02T00:00:00Z",
        ),
    )

    assert "**Launch posture:** No deploy-blocking findings in supplied evidence" in report
    assert "No findings were provided for this report." in report
    assert "No detailed findings." in report
