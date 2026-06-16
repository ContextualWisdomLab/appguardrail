import os
import re
import tempfile
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.cli.vibesec import _collect_files, _print_scan_results, _scan_file, cmd_init, cmd_scan, cmd_review, REVIEW_PROMPT_BASE, REVIEW_PROMPT_NEXTJS, REVIEW_PROMPT_SUPABASE, REVIEW_PROMPT_FIREBASE, REVIEW_PROMPT_STRIPE, REVIEW_PROMPT_FOOTER

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
        "pattern": re.compile(r"TODO: fix issue"),
        "severity": "HIGH",
        "message": "Found issue todo",
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
    def __init__(self, path):
        self.path = str(path)


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
    test_file.write_text("const key = MOCK_SECRET_KEY;\n// TODO: fix issue here\n")

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


def test_collect_files_handles_oserror_in_scandir(tmp_path):
    (tmp_path / "a.py").touch()
    with patch("os.scandir", side_effect=PermissionError):
        assert list(_collect_files(tmp_path)) == []


def test_collect_files_handles_oserror_in_entry(tmp_path):
    (tmp_path / "a.py").touch()
    (tmp_path / "b.py").touch()

    original_scandir = os.scandir

    def mock_scandir(path):
        iterator = original_scandir(path)
        class MockIterator:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                iterator.close()
            def __iter__(self):
                return self
            def __next__(self):
                entry = next(iterator)
                if entry.name == "a.py":
                    class MockEntry:
                        name = entry.name
                        path = entry.path
                        def is_symlink(self):
                            raise PermissionError("Access denied")
                    return MockEntry()
                return entry
        return MockIterator()

    with patch("os.scandir", side_effect=mock_scandir):
        collected_rel_paths = {f.relative_to(tmp_path).as_posix() for f in _collect_files(tmp_path)}
        assert collected_rel_paths == {"b.py"}



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


def test_scan_file_stat_error(tmp_path):
    test_file = tmp_path / "stat_error.ts"
    test_file.write_text("const key = 'x';\n")

    with patch("scanner.cli.vibesec.os.lstat", side_effect=PermissionError("Permission denied")) as mock_permission:
        assert _scan_file(test_file, tmp_path) == []
        mock_permission.assert_called_once()

    with patch("scanner.cli.vibesec.os.lstat", side_effect=OSError("OS error")) as mock_oserror:
        assert _scan_file(test_file, tmp_path) == []
        mock_oserror.assert_called_once()


def test_collect_files_oserror_on_scandir(tmp_path):
    (tmp_path / "dir1").mkdir()
    (tmp_path / "dir1" / "file1.py").touch()
    (tmp_path / "file2.py").touch()

    original_scandir = os.scandir
    def mock_scandir(path):
        if Path(path).name == "dir1":
            raise PermissionError("Access denied")
        return original_scandir(path)

    with patch("os.scandir", side_effect=mock_scandir):
        files = list(_collect_files(tmp_path))
        assert len(files) == 1
        assert files[0].name == "file2.py"

def test_collect_files_oserror_on_entry(tmp_path):
    (tmp_path / "file1.py").touch()
    (tmp_path / "file2.py").touch()

    original_scandir = os.scandir
    def mock_scandir(path):
        class MockEntry:
            def __init__(self, entry):
                self._entry = entry
                self.name = entry.name
                self.path = entry.path
            def is_symlink(self):
                return self._entry.is_symlink()
            def is_dir(self, follow_symlinks=False):
                if self.name == "file1.py":
                    raise PermissionError("Access denied")
                return self._entry.is_dir(follow_symlinks=follow_symlinks)
            def is_file(self, follow_symlinks=False):
                return self._entry.is_file(follow_symlinks=follow_symlinks)

        class MockIterator:
            def __init__(self, it):
                self.it = it
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.it.close()
            def __iter__(self):
                for entry in self.it:
                    yield MockEntry(entry)

        return MockIterator(original_scandir(path))

    with patch("os.scandir", side_effect=mock_scandir):
        files = list(_collect_files(tmp_path))
        assert len(files) == 1
        assert files[0].name == "file2.py"
# ---------------------------------------------------------------------------
# cmd_review tests
# ---------------------------------------------------------------------------

def test_cmd_review_base_prompt(capsys):
    args = Namespace(stack=None, db=None, payments=None)
    cmd_review(args)
    captured = capsys.readouterr()
    assert REVIEW_PROMPT_BASE in captured.out
    assert REVIEW_PROMPT_FOOTER in captured.out
    assert REVIEW_PROMPT_NEXTJS not in captured.out
    assert REVIEW_PROMPT_SUPABASE not in captured.out
    assert REVIEW_PROMPT_FIREBASE not in captured.out
    assert REVIEW_PROMPT_STRIPE not in captured.out

def test_cmd_review_nextjs(capsys):
    args = Namespace(stack=["nextjs"], db=None, payments=None)
    cmd_review(args)
    captured = capsys.readouterr()
    assert REVIEW_PROMPT_NEXTJS in captured.out

def test_cmd_review_supabase(capsys):
    args = Namespace(stack=None, db="supabase", payments=None)
    cmd_review(args)
    captured = capsys.readouterr()
    assert REVIEW_PROMPT_SUPABASE in captured.out

def test_cmd_review_supabase_via_stack(capsys):
    args = Namespace(stack=["supabase"], db=None, payments=None)
    cmd_review(args)
    captured = capsys.readouterr()
    assert REVIEW_PROMPT_SUPABASE in captured.out

def test_cmd_review_firebase(capsys):
    args = Namespace(stack=None, db="firebase", payments=None)
    cmd_review(args)
    captured = capsys.readouterr()
    assert REVIEW_PROMPT_FIREBASE in captured.out

def test_cmd_review_firebase_via_stack(capsys):
    args = Namespace(stack=["firebase"], db=None, payments=None)
    cmd_review(args)
    captured = capsys.readouterr()
    assert REVIEW_PROMPT_FIREBASE in captured.out

def test_cmd_review_stripe(capsys):
    args = Namespace(stack=None, db=None, payments="stripe")
    cmd_review(args)
    captured = capsys.readouterr()
    assert REVIEW_PROMPT_STRIPE in captured.out

def test_cmd_review_all_options(capsys):
    args = Namespace(stack=["nextjs"], db="supabase", payments="stripe")
    cmd_review(args)
    captured = capsys.readouterr()
    assert REVIEW_PROMPT_BASE in captured.out
    assert REVIEW_PROMPT_NEXTJS in captured.out
    assert REVIEW_PROMPT_SUPABASE in captured.out
    assert REVIEW_PROMPT_STRIPE in captured.out
    assert REVIEW_PROMPT_FOOTER in captured.out


def test_scan_file_large_file(tmp_path):
    test_file = tmp_path / "large_file.ts"
    test_file.write_text("const key = 'x';\n")

    original_lstat = os.lstat

    def mock_lstat(path):
        st = original_lstat(path)
        return os.stat_result(
            (
                st.st_mode,
                st.st_ino,
                st.st_dev,
                st.st_nlink,
                st.st_uid,
                st.st_gid,
                10 * 1024 * 1024 + 1,
                st.st_atime,
                st.st_mtime,
                st.st_ctime,
            )
        )

    with patch("scanner.cli.vibesec.os.lstat", side_effect=mock_lstat) as mock_large:
        assert _scan_file(test_file, tmp_path) == []
        mock_large.assert_called_once()
