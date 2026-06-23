import json
import re
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.cli.vibesec import _collect_files, _print_scan_results, _run_trivy_fs, _scan_file, cmd_init, cmd_scan

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


class ScanArgs:
    def __init__(self, path, trivy=False):
        self.path = str(path)
        self.trivy = trivy


def _create_symlink(target, link, target_is_directory=False):
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks are not available in this environment: {exc}")


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


def test_scan_file_rule_cache_invalidates_when_scan_rules_change(tmp_path):
    test_file = tmp_path / "unsafe.py"
    test_file.write_text("FIRST_TOKEN\nSECOND_TOKEN\n")

    first_rules = [{
        "id": "first",
        "pattern": re.compile(r"FIRST_TOKEN"),
        "severity": "HIGH",
        "message": "first token",
        "extensions": [".py"],
    }]
    second_rules = [{
        "id": "second",
        "pattern": re.compile(r"SECOND_TOKEN"),
        "severity": "HIGH",
        "message": "second token",
        "extensions": [".py"],
    }]

    with patch("scanner.cli.vibesec.SCAN_RULES", first_rules):
        assert [finding["rule_id"] for finding in _scan_file(test_file, tmp_path)] == ["first"]

    with patch("scanner.cli.vibesec.SCAN_RULES", second_rules):
        assert [finding["rule_id"] for finding in _scan_file(test_file, tmp_path)] == ["second"]


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


def test_collect_files_skips_file_symlink(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("print('target')\n")
    link = tmp_path / "linked.py"
    _create_symlink(target, link)

    collected_rel_paths = {f.relative_to(tmp_path).as_posix() for f in _collect_files(tmp_path)}

    assert "target.py" in collected_rel_paths
    assert "linked.py" not in collected_rel_paths


def test_collect_files_skips_dir_symlink(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "nested.py").write_text("print('nested')\n")
    link = tmp_path / "linked_dir"
    _create_symlink(real_dir, link, target_is_directory=True)

    collected_rel_paths = {f.relative_to(tmp_path).as_posix() for f in _collect_files(tmp_path)}

    assert "real/nested.py" in collected_rel_paths
    assert "linked_dir/nested.py" not in collected_rel_paths


def test_collect_files_handles_broken_symlink(tmp_path):
    link = tmp_path / "broken.py"
    _create_symlink(tmp_path / "missing.py", link)

    assert list(_collect_files(tmp_path)) == []


def test_collect_files_handles_cyclic_symlink(tmp_path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "a.py").write_text("print('a')\n")
    (dir_b / "b.py").write_text("print('b')\n")
    _create_symlink(dir_b, dir_a / "to_b", target_is_directory=True)
    _create_symlink(dir_a, dir_b / "to_a", target_is_directory=True)

    collected_rel_paths = {f.relative_to(tmp_path).as_posix() for f in _collect_files(tmp_path)}

    assert collected_rel_paths == {"a/a.py", "b/b.py"}


@patch("scanner.cli.vibesec.SCAN_RULES", MOCK_RULES)
def test_scan_file_skips_symlink(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("MOCK_SECRET_KEY\n")
    link = tmp_path / "linked.py"
    _create_symlink(target, link)

    assert _scan_file(link, tmp_path) == []


def test_cmd_scan_skips_symlink_path(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text("print('target')\n")
    link = tmp_path / "linked.py"
    _create_symlink(target, link)

    assert cmd_scan(ScanArgs(link)) == 0
    assert "Skipping symlink path:" in capsys.readouterr().out


def test_cmd_scan_returns_failure_when_no_files_scanned(tmp_path, capsys):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "index.js").write_text("console.log('ignored')\n")

    assert cmd_scan(ScanArgs(tmp_path)) == 1
    out = capsys.readouterr().out
    assert "No files were scanned. Are you in the right directory?" in out
    assert "Scanned 0 files" in out


def test_run_trivy_fs_maps_json_findings(tmp_path):
    report = {
        "Results": [{
            "Target": str(tmp_path / "package-lock.json"),
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-0001",
                "PkgName": "leftpad",
                "InstalledVersion": "1.0.0",
                "FixedVersion": "1.0.1",
                "Severity": "HIGH",
                "Title": "demo vuln",
            }],
            "Misconfigurations": [{
                "ID": "AVD-DS-0001",
                "Severity": "MEDIUM",
                "Title": "Dockerfile root user",
                "Message": "Container runs as root",
                "CauseMetadata": {"StartLine": 7},
            }],
            "Secrets": [{
                "RuleID": "private-key",
                "Severity": "CRITICAL",
                "Title": "Private key",
                "StartLine": 3,
                "Match": "SHOULD_NOT_PRINT",
            }],
        }]
    }
    process = type("Process", (), {"returncode": 0, "stdout": json.dumps(report), "stderr": ""})()

    with patch("scanner.cli.vibesec.shutil.which", return_value="/usr/bin/trivy"), \
         patch("scanner.cli.vibesec.subprocess.run", return_value=process) as run:
        findings = _run_trivy_fs(tmp_path)

    assert run.call_args.args[0][:2] == ["/usr/bin/trivy", "fs"]
    assert [finding["rule_id"] for finding in findings] == [
        "trivy:CVE-2026-0001",
        "trivy:AVD-DS-0001",
        "trivy:private-key",
    ]
    assert findings[0]["file"] == "package-lock.json"
    assert findings[1]["severity"] == "WARNING"
    assert findings[1]["line"] == 7
    assert findings[2]["severity"] == "CRITICAL"
    assert findings[0]["source"] == "trivy"
    assert findings[0]["category"] == "dependency"
    assert findings[0]["context"] == "app-code"
    assert findings[0]["fix_prompt"].startswith("Fix trivy:CVE-2026-0001")
    assert "SHOULD_NOT_PRINT" not in findings[2]["snippet"]


def test_run_trivy_fs_requires_trivy(tmp_path):
    with patch("scanner.cli.vibesec.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="trivy executable not found"):
            _run_trivy_fs(tmp_path)


@patch("scanner.cli.vibesec.SCAN_RULES", MOCK_RULES)
def test_cmd_scan_does_not_block_doc_findings(tmp_path, capsys):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "example.md").write_text("MOCK_SECRET_KEY\n")

    assert cmd_scan(ScanArgs(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "| doc" in out
    assert "Gate:    non-blocking context" in out
    assert "🔴 0 critical" in out


@patch("scanner.cli.vibesec.SCAN_RULES", MOCK_RULES)
def test_cmd_scan_blocks_app_code_findings(tmp_path, capsys):
    (tmp_path / "app.py").write_text("MOCK_SECRET_KEY\n")

    assert cmd_scan(ScanArgs(tmp_path)) == 1
    out = capsys.readouterr().out
    assert "| app-code" in out
    assert "🔴 1 critical" in out


def test_cmd_scan_does_not_block_embedded_scanner_rule_fixtures(tmp_path, capsys):
    scanner_cli = tmp_path / "scanner" / "cli"
    scanner_cli.mkdir(parents=True)
    (scanner_cli / "vibesec.py").write_text('"message": "Use eval() detected"\n')
    rules = [{
        "id": "dangerous-eval",
        "pattern": re.compile(r"eval"),
        "severity": "CRITICAL",
        "message": "eval detected",
        "extensions": [".py"],
    }]

    with patch("scanner.cli.vibesec.SCAN_RULES", rules):
        assert cmd_scan(ScanArgs(tmp_path)) == 0

    out = capsys.readouterr().out
    assert "| scanner-fixture" in out
    assert "🔴 0 critical" in out


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
    assert "Rule:    VSEC-001" in captured.out
    assert "Found a critical issue" in captured.out
    assert "Code:    const secret = 'abc';" in captured.out
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
    assert "🟡 1 warning" in captured.out
    assert "✅ No deploy-blocking critical or high issues found." in captured.out


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


def test_sanitize_terminal_output():
    from scanner.cli.vibesec import _sanitize_terminal_output
    # Test normal strings
    assert _sanitize_terminal_output("normal string") == "normal string"
    assert _sanitize_terminal_output("tabs\tare\tallowed") == "tabs\tare\tallowed"

    # Test ANSI escape sequences (e.g. \033[2K clears line)
    assert _sanitize_terminal_output("malicious\033[2K") == "malicious\\x1b[2K"

    # Test carriage return and newline
    assert _sanitize_terminal_output("hidden\rmessage") == "hidden\\rmessage"
    assert _sanitize_terminal_output("line1\nline2") == "line1\\nline2"

    # Test non-strings
    assert _sanitize_terminal_output(None) is None
