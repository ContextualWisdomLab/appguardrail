"""Regression tests for AppGuardrail scanning its commercial-readiness loop."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


ROOT = Path(__file__).resolve().parents[1]
LOOP_MODULE = ROOT / "scripts" / "ci" / "commercial_readiness_loop.py"


def test_commercial_gap_registry_does_not_trigger_auth_deferral_rule() -> None:
    """Reviewed product objectives must not look like deferred authentication work."""
    findings = _scan_file(LOOP_MODULE, ROOT)

    assert [
        finding
        for finding in findings
        if finding["rule_id"] == "todo-skip-auth"
    ] == []
