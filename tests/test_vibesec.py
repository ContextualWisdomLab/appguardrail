import re
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.cli.vibesec import _collect_files, _print_scan_results, _scan_file, cmd_init

MOCK_RULES = [
    {
        "id": "mock-secret",
        "pattern": re.compile(r"MOCK_SECRET_KEY"),
        "severity": "CRITICAL",
        "message": "Found mock secret",
        "extensions": None,
    },
    {
        "id": "mock-todo",
        "pattern": re.compile(r"TODO: fix auth"),
        "severity": "HIGH",
        "message": "Found auth todo",
        "extensions": None,
    },
    {
        "id": "mock-rules-ext",
        "pattern": re.compile(r"allow all"),
        "severity": "CRITICAL",
        "message": "Allows all",
        "extensions": [".rules"],
    },
]


class Args:
    def __init__(self, tool="cursor", stack=None):
        self.tool = tool
        self.stack = stack


def test_scan_file_error_handling(tmp_path):
    test_file = tmp_path / "unsafe.ts"
    test_file.write_text("const key = 'x';\n")

    with patch.object(Path, "open", side_effect=PermissionError("Permission denied")):
        assert _scan_file(test_file, tmp_path) == []

    with patch.object(Path, "open", side_effect=OSError("OS error")):
        assert _scan_file(test_file, tmp_path) == []


@patch("scanner.cli.vibesec.SCAN_RULES", MOCK_RULES)
def test_scan_file_no_findings(tmp_path):
    test_file = tmp_path / "safe.py"
    test_file.write_text("print('hello')\n")
    assert _scan_file(test_file, tmp_path) == []


@patch("scanner.cli.vibesec.SCAN_RULES", MOCK_RULES)
def test_scan_file_with_findings(tmp_path):
    test_file = tmp_path / "unsafe.ts"
    test_file.write_text("const key = MOCK_SECRET_KEY;\n")

    findings = _scan_file(test_file, tmp_path)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "mock-secret"


@patch("scanner.cli.vibesec.SCAN_RULES", MOCK_RULES)
def test_scan_file_with_multiple_findings(tmp_path):
    test_file = tmp_path / "unsafe_multiple.js"
    test_file.write_text("const key = MOCK_SECRET_KEY;\n// TODO: fix auth checks here\n")

    findings = _scan_file(test_file, tmp_path)
    rule_ids = [f["rule_id"] for f in findings]
    assert len(findings) == 2
    assert "mock-secret" in rule_ids
    assert "mock-todo" in rule_ids


def test_scan_file_unreadable(tmp_path):
    test_file = tmp_path / "unreadable.ts"
    test_file.write_text("MOCK_SECRET_KEY\n")

    with patch.object(Path, "open", side_effect=PermissionError("Permission denied")):
        assert _scan_file(test_file, tmp_path) == []


@patch("scanner.cli.vibesec.SCAN_RULES", MOCK_RULES)
def test_scan_file_extensions_filter(tmp_path):
    test_file = tmp_path / "rules.js"
    test_file.write_text("allow all\n")

    findings = _scan_file(test_file, tmp_path)
    rule_ids = [f["rule_id"] for f in findings]
    assert "mock-rules-ext" not in rule_ids

    test_file_rules = tmp_path / "firestore.rules"
    test_file_rules.write_text("allow all\n")

    findings = _scan_file(test_file_rules, tmp_path)
    rule_ids = [f["rule_id"] for f in findings]
    assert "mock-rules-ext" in rule_ids


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


def test_cmd_init_cursor(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="cursor"))

    assert (tmp_path / ".cursor" / "rules" / "vibesec.md").exists()
    assert (tmp_path / "VIBESEC_CHECKLIST.md").exists()
    captured = capsys.readouterr()
    assert "✅ VibeSec initialized successfully!" in captured.out
    assert ".cursor/rules/vibesec.md" in captured.out


def test_cmd_init_claude_code_new(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="claude-code"))

    assert (tmp_path / "CLAUDE.md").exists()
    assert (tmp_path / "VIBESEC_CHECKLIST.md").exists()


def test_cmd_init_claude_code_append(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    claude_file = tmp_path / "CLAUDE.md"
    claude_file.write_text("Existing rules\n")

    cmd_init(Args(tool="claude-code"))

    content = claude_file.read_text()
    assert "Existing rules" in content
    assert len(content.splitlines()) > 1
    assert "CLAUDE.md (appended)" in capsys.readouterr().out


def test_cmd_init_claude_code_skip(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    claude_file = tmp_path / "CLAUDE.md"
    claude_file.write_text("VibeSec existing rules\n")

    cmd_init(Args(tool="claude-code"))

    assert claude_file.read_text() == "VibeSec existing rules\n"
    assert "CLAUDE.md already contains VibeSec rules — skipping." in capsys.readouterr().out


def test_cmd_init_windsurf(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="windsurf"))

    assert (tmp_path / ".windsurf" / "rules" / "vibesec.md").exists()
    assert (tmp_path / "VIBESEC_CHECKLIST.md").exists()
    assert ".windsurf/rules/vibesec.md" in capsys.readouterr().out


def test_cmd_init_lovable(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="lovable"))

    assert not (tmp_path / ".lovable").exists()
    assert (tmp_path / "VIBESEC_CHECKLIST.md").exists()
    assert "VIBESEC_CHECKLIST.md" in capsys.readouterr().out


def test_cmd_init_unknown_tool(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        cmd_init(Args(tool="invalid-tool"))

    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Unknown tool: invalid-tool" in captured.out
    assert "Supported tools: cursor, claude-code, windsurf, lovable" in captured.out


def test_cmd_init_supabase_stack(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(stack="nextjs-supabase"))

    captured = capsys.readouterr()
    assert "Supabase stack detected. Quick reminders:" in captured.out
    assert "Enable RLS on every user-data table" in captured.out
