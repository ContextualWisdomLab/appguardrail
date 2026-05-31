import tempfile
from pathlib import Path
from unittest.mock import patch

from scanner.cli.vibesec import _collect_files, _print_scan_results, _scan_file


def test_scan_file_error_handling(tmp_path):
    test_file = tmp_path / "unsafe.ts"
    test_file.write_text("const key = 'x';\n")

    with patch.object(Path, "open", side_effect=PermissionError("Permission denied")):
        assert _scan_file(test_file, tmp_path) == []

    with patch.object(Path, "open", side_effect=OSError("OS error")):
        assert _scan_file(test_file, tmp_path) == []


def test_collect_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = Path(tmpdir)
        (base_path / "src").mkdir()
        (base_path / "src" / "main.py").touch()
        (base_path / "src" / "utils.js").touch()
        (base_path / "README.md").touch()
        (base_path / "node_modules").mkdir()
        (base_path / "node_modules" / "index.js").touch()
        (base_path / ".git").mkdir()
        (base_path / ".git" / "config").touch()
        (base_path / "src" / "image.png").touch()
        (base_path / "package.lock").touch()

        collected_files = list(_collect_files(base_path))
        collected_rel_paths = {f.relative_to(base_path).as_posix() for f in collected_files}

        assert collected_rel_paths == {"src/main.py", "src/utils.js", "README.md"}
        assert "node_modules/index.js" not in collected_rel_paths
        assert ".git/config" not in collected_rel_paths
        assert "src/image.png" not in collected_rel_paths
        assert "package.lock" not in collected_rel_paths


def test_print_scan_results_empty(capsys):
    _print_scan_results([], 5)
    captured = capsys.readouterr()

    assert "Scanned 5 files" in captured.out
    assert "🔴 0 critical" in captured.out
    assert "✅ No issues found in this scan." in captured.out
    assert "Run 'vibesec review'" not in captured.out


def test_print_scan_results_critical(capsys):
    findings = [{
        "severity": "CRITICAL",
        "file": "app/page.tsx",
        "line": 10,
        "rule_id": "VSEC-001",
        "message": "Found a critical issue",
        "snippet": "const secret = 'abc';",
    }]
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
    findings = [{
        "severity": "HIGH",
        "file": "app/api/route.ts",
        "line": 5,
        "rule_id": "VSEC-002",
        "message": "Found a high issue",
        "snippet": "export async function GET() {}",
    }]
    _print_scan_results(findings, 3)
    captured = capsys.readouterr()

    assert "[🟠 HIGH] app/api/route.ts:5" in captured.out
    assert "🟠 1 high" in captured.out
    assert "⚠️  High-severity issues found. Review before deploying." in captured.out


def test_print_scan_results_warnings_only(capsys):
    findings = [{
        "severity": "WARNING",
        "file": "utils.ts",
        "line": 1,
        "rule_id": "VSEC-003",
        "message": "Found a warning",
        "snippet": "console.log(data);",
    }]
    _print_scan_results(findings, 1)
    captured = capsys.readouterr()

    assert "[🟡 WARNING] utils.ts:1" in captured.out
    assert "🟡 1 warnings" in captured.out
    assert "✅ No critical or high-severity issues found." in captured.out


def test_print_scan_results_sorting(capsys):
    findings = [
        {"severity": "INFO", "file": "info.ts", "line": 1, "rule_id": "VSEC-004", "message": "Info message", "snippet": "info"},
        {"severity": "CRITICAL", "file": "crit.ts", "line": 2, "rule_id": "VSEC-001", "message": "Crit message", "snippet": "crit"},
        {"severity": "HIGH", "file": "high.ts", "line": 3, "rule_id": "VSEC-002", "message": "High message", "snippet": "high"},
        {"severity": "WARNING", "file": "warn.ts", "line": 4, "rule_id": "VSEC-003", "message": "Warn message", "snippet": "warn"},
    ]
    _print_scan_results(findings, 4)
    out = capsys.readouterr().out

    idx_crit = out.find("[🔴 CRITICAL]")
    idx_high = out.find("[🟠 HIGH]")
    idx_warn = out.find("[🟡 WARNING]")
    idx_info = out.find("[🔵 INFO]")

    assert idx_crit != -1
    assert idx_high != -1
    assert idx_warn != -1
    assert idx_info != -1
    assert idx_crit < idx_high < idx_warn < idx_info
