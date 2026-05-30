import pytest
from scanner.cli.vibesec import _print_scan_results

def test_print_scan_results_empty(capsys):
    _print_scan_results([], 5)
    captured = capsys.readouterr()

    assert "Scanned 5 files" in captured.out
    assert "🔴 0 critical" in captured.out
    assert "✅ No issues found in this scan." in captured.out
    assert "Run 'vibesec review'" not in captured.out

def test_print_scan_results_critical(capsys):
    findings = [
        {
            "severity": "CRITICAL",
            "file": "app/page.tsx",
            "line": 10,
            "rule_id": "VSEC-001",
            "message": "Found a critical issue",
            "snippet": "const secret = 'abc';"
        }
    ]
    _print_scan_results(findings, 2)
    captured = capsys.readouterr()

    assert "[🔴 CRITICAL] app/page.tsx:10" in captured.out
    assert "Rule: VSEC-001" in captured.out
    assert "Found a critical issue" in captured.out
    assert "Code: const secret = 'abc';" in captured.out
    assert "🔴 1 critical" in captured.out
    assert "❌ Critical issues found. Fix before deploying." in captured.out
    assert "💡 Run 'vibesec review' to get an AI prompt for fixing these issues." in captured.out

def test_print_scan_results_high(capsys):
    findings = [
        {
            "severity": "HIGH",
            "file": "app/api/route.ts",
            "line": 5,
            "rule_id": "VSEC-002",
            "message": "Found a high issue",
            "snippet": "export async function GET() {}"
        }
    ]
    _print_scan_results(findings, 3)
    captured = capsys.readouterr()

    assert "[🟠 HIGH] app/api/route.ts:5" in captured.out
    assert "🟠 1 high" in captured.out
    assert "⚠️  High-severity issues found. Review before deploying." in captured.out

def test_print_scan_results_warnings_only(capsys):
    findings = [
        {
            "severity": "WARNING",
            "file": "utils.ts",
            "line": 1,
            "rule_id": "VSEC-003",
            "message": "Found a warning",
            "snippet": "console.log(data);"
        }
    ]
    _print_scan_results(findings, 1)
    captured = capsys.readouterr()

    assert "[🟡 WARNING] utils.ts:1" in captured.out
    assert "🟡 1 warnings" in captured.out
    assert "✅ No critical or high-severity issues found." in captured.out

def test_print_scan_results_sorting(capsys):
    findings = [
        {
            "severity": "INFO",
            "file": "info.ts",
            "line": 1,
            "rule_id": "VSEC-004",
            "message": "Info message",
            "snippet": "info"
        },
        {
            "severity": "CRITICAL",
            "file": "crit.ts",
            "line": 2,
            "rule_id": "VSEC-001",
            "message": "Crit message",
            "snippet": "crit"
        },
        {
            "severity": "HIGH",
            "file": "high.ts",
            "line": 3,
            "rule_id": "VSEC-002",
            "message": "High message",
            "snippet": "high"
        },
        {
            "severity": "WARNING",
            "file": "warn.ts",
            "line": 4,
            "rule_id": "VSEC-003",
            "message": "Warn message",
            "snippet": "warn"
        }
    ]
    _print_scan_results(findings, 4)
    captured = capsys.readouterr()

    out = captured.out
    idx_crit = out.find("[🔴 CRITICAL]")
    idx_high = out.find("[🟠 HIGH]")
    idx_warn = out.find("[🟡 WARNING]")
    idx_info = out.find("[🔵 INFO]")

    assert idx_crit != -1
    assert idx_high != -1
    assert idx_warn != -1
    assert idx_info != -1

    assert idx_crit < idx_high
    assert idx_high < idx_warn
    assert idx_warn < idx_info
