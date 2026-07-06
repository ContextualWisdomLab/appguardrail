import pytest

from appguardrail_core.reports import (
    REPORT_TYPE_LABELS,
    ReportContext,
    render_html,
    supported_report_types,
)


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
    ]


def hostile_findings():
    return [
        {
            "rule_id": "xss-template-injection",
            "severity": "CRITICAL",
            "message": "<script>alert('pwned')</script> reflected in template output.",
            "file": "app/views.py",
            "line": 12,
            "snippet": "<script>document.cookie</script>",
            "category": "injection",
            "context": "app-code",
            "remediation": "Escape user input before rendering & use safe templates.",
            "verification": "Rerun AppGuardrail after remediation.",
        },
    ]


def context():
    return ReportContext(
        app_name="Demo SaaS",
        repository="ContextualWisdomLab/demo",
        commit="abc123",
        generated_at="2026-07-02T00:00:00Z",
    )


def test_render_html_produces_self_contained_document():
    html = render_html("buyer-diligence", sample_findings(), context())

    assert html.startswith("<!doctype html>")
    assert "</html>" in html
    assert "<style>" in html
    assert "<title>AppGuardrail — Buyer diligence report</title>" in html
    assert "<h1>AppGuardrail Buyer Diligence Report</h1>" in html
    # Self-contained: no external assets.
    assert "http://" not in html
    assert "https://" not in html
    assert 'src="' not in html
    assert "@import" not in html


def test_render_html_covers_all_report_types():
    for report_type in supported_report_types():
        html = render_html(report_type, sample_findings(), context())
        assert html.startswith("<!doctype html>")
        assert REPORT_TYPE_LABELS[report_type] in html


def test_render_html_escapes_hostile_finding_content():
    html = render_html("buyer-diligence", hostile_findings(), context())

    assert "<script>" not in html
    assert "</script>" not in html
    assert "&lt;script&gt;" in html
    # Ampersand in the remediation text is escaped, not passed through raw.
    assert "input before rendering &amp; use safe" in html


def test_render_html_converts_headings_and_tables():
    html = render_html("buyer-diligence", sample_findings(), context())

    assert "<h2>Executive Readout</h2>" in html
    assert "<table>" in html
    assert "<tr><th>Severity</th><th>Count</th></tr>" in html
    assert "<td>High</td>" in html
    # Separator rows (|---|---:|) must not leak into the output.
    assert "---" not in html


def test_render_html_converts_inline_markdown_and_lists():
    html = render_html("founder-friendly", sample_findings(), context())

    assert "<strong>App:</strong>" in html
    assert "<ul><li>" in html
    assert "<pre><code>" in html
    assert "**" not in html


def test_render_html_rejects_unsupported_type():
    with pytest.raises(ValueError):
        render_html("nonexistent", sample_findings(), context())
