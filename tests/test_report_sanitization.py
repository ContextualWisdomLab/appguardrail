"""Reports must neutralize hostile finding content (stored-XSS via markdown)."""

import pytest

from appguardrail_core.reports import render_report, supported_report_types

HOSTILE = {
    "severity": "HIGH",
    "rule_id": "x",
    "message": "<script>alert(1)</script> <img src=x onerror=alert(2)>",
    "remediation": "run <b>evil</b>",
    "verification": "check <iframe>",
    "file": "a.ts",
    "line": 1,
    "context": "app-code",
    "snippet": "before ``` break out ``` after",
    "owasp": ["A03:2021"],
}


@pytest.mark.parametrize("report_type", supported_report_types())
def test_no_raw_html_in_any_report(report_type):
    report = render_report(report_type, [HOSTILE])
    # active markup must be escaped, not passed through
    assert "<script>" not in report
    assert "onerror=" not in report or "&gt;" in report  # tag broken up
    assert "<iframe>" not in report
    assert "<b>evil</b>" not in report


def test_escapes_to_entities():
    report = render_report("buyer-diligence", [HOSTILE])
    assert "&lt;script&gt;" in report
    assert "&lt;b&gt;evil&lt;/b&gt;" in report


def test_snippet_cannot_break_code_fence():
    report = render_report("buyer-diligence", [HOSTILE])
    # the raw triple-backtick from the snippet must be neutralized (zero-width
    # joiner inserted) so it can't close the ```text fence early
    assert "``` break out ```" not in report


def test_benign_message_unchanged():
    benign = {
        **HOSTILE,
        "message": "Hardcoded secret detected",
        "remediation": "move to env",
        "verification": "rerun",
        "snippet": "const k = 1",
    }
    report = render_report("founder-friendly", [benign])
    assert "Hardcoded secret detected" in report  # no over-escaping
