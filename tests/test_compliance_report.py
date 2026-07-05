"""Tests for the compliance (OWASP -> SOC 2 / ISO 27001) report."""

from appguardrail_core.reports import (
    render_compliance_report,
    render_report,
    supported_report_types,
)

FINDINGS = [
    {"severity": "CRITICAL", "rule_id": "hardcoded-aws-access-key-id",
     "message": "AWS key", "file": "a.ts", "line": 3, "owasp": ["A07:2021"],
     "context": "app-code"},
    {"severity": "HIGH", "rule_id": "sql-injection-raw-unsafe", "message": "SQLi",
     "file": "b.ts", "line": 9, "owasp": ["OWASP A03:2021 - Injection"],
     "context": "app-code"},
    {"severity": "WARNING", "rule_id": "nextjs-missing-security-headers",
     "message": "headers", "file": "c.ts", "line": 1, "owasp": ["A05:2021"],
     "context": "app-code"},
    {"severity": "INFO", "rule_id": "no-owasp", "message": "misc", "file": "d.ts",
     "line": 1, "context": "app-code"},
]


def test_compliance_registered():
    assert "compliance" in supported_report_types()
    # render_report dispatch works too
    assert "Compliance Evidence" in render_report("compliance", FINDINGS)


def test_control_coverage_and_status():
    report = render_compliance_report(FINDINGS)
    # crosswalk headers
    assert "SOC 2" in report and "ISO 27001" in report
    # A03 injection is blocking -> Gap; A05 non-blocking -> Observed
    assert "| A03 | Injection |" in report
    a03 = next(l for l in report.splitlines() if l.startswith("| A03 |"))
    assert "Gap - 1 blocking" in a03
    a05 = next(l for l in report.splitlines() if l.startswith("| A05 |"))
    assert "Observed (non-blocking)" in a05
    a07 = next(l for l in report.splitlines() if l.startswith("| A07 |"))
    assert "Gap - 1 blocking" in a07
    # A01 with no findings
    a01 = next(l for l in report.splitlines() if l.startswith("| A01 |"))
    assert "No findings" in a01


def test_unmapped_findings_counted():
    report = render_compliance_report(FINDINGS)
    assert "**Findings without an OWASP mapping:** 1" in report


def test_parses_both_owasp_formats():
    # bare "A03:2021" and "OWASP A03:2021 - Injection" both land under A03
    report = render_compliance_report(FINDINGS)
    a03 = next(l for l in report.splitlines() if l.startswith("| A03 |"))
    assert "| 1 |" in a03  # the OWASP-prefixed one mapped correctly


def test_empty_findings():
    report = render_compliance_report([])
    assert "No findings" in report
    assert "**Findings without an OWASP mapping:** 0" in report
