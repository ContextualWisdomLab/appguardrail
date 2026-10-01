"""Production-scanner regressions over pinned Clearfolio authorization fixtures."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_RULE_ID = "java-spring-admin-discarded-tenant-context"
_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_VULNERABLE_FIXTURE = _FIXTURE_DIR / "clearfolio_admin_controller_vulnerable.java"
_FIXED_FIXTURE = _FIXTURE_DIR / "clearfolio_admin_controller_fixed.java"
_EXPECTED_VULNERABLE_SINKS = (
    "conversionService.getAllJobs()",
    "conversionService.deleteJob(jobId)",
    "conversionService.retryDeadLettered(",
)


def _fixture_findings(path: Path) -> list[dict]:
    """Return this detector's findings when scanning one immutable fixture directly."""
    return [
        finding
        for finding in _scan_file(path, path.parent)
        if finding["rule_id"] == _RULE_ID
    ]


def test_scan_file_detects_each_sink_in_pinned_vulnerable_fixture() -> None:
    """Bind production-scanner evidence to every vulnerable sink in the pinned blob."""
    source = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")
    for sink in _EXPECTED_VULNERABLE_SINKS:
        assert sink in source

    findings = _fixture_findings(_VULNERABLE_FIXTURE)
    assert len(findings) == len(_EXPECTED_VULNERABLE_SINKS)
    assert all(finding["severity"] == "HIGH" for finding in findings)
    assert all(finding["source"] == "appguardrail-rule" for finding in findings)
    assert all(finding["category"] == "authz" for finding in findings)
    assert all(finding["confidence"] == "high" for finding in findings)
    assert all(
        finding["file"] == _VULNERABLE_FIXTURE.name for finding in findings
    )
    assert all(
        finding["cwe"] == ("CWE-863 - Incorrect Authorization",)
        for finding in findings
    )
    assert all(
        "Capture the returned TenantContext" in finding["message"]
        for finding in findings
    )


def test_scan_file_keeps_pinned_reviewed_fixed_fixture_clean() -> None:
    """Bind the negative production-scanner oracle to the complete reviewed fixed blob."""
    assert _fixture_findings(_FIXED_FIXTURE) == []
