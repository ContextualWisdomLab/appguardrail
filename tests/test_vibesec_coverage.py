import os
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.cli.vibesec import cmd_init, cmd_scan
from tests.test_vibesec import MOCK_RULES


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


def test_cmd_init_symlink_removal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target_dir = tmp_path / ".cursor" / "rules"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / "vibesec.md"

    # Create a dummy file to symlink to
    dummy = tmp_path / "dummy.md"
    dummy.write_text("dummy")
    _create_symlink(dummy, target_file)

    checklist = tmp_path / "VIBESEC_CHECKLIST.md"
    _create_symlink(dummy, checklist)

    cmd_init(Args(tool="cursor"))

    # Both should be regular files now, not symlinks
    assert target_file.exists()
    assert not target_file.is_symlink()
    assert checklist.exists()
    assert not checklist.is_symlink()


def test_cmd_init_append_marker_no_marker(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    claude_file = tmp_path / "CLAUDE.md"
    claude_file.write_text("No marker here.\n")

    cmd_init(Args(tool="claude-code"))

    content = claude_file.read_text()
    assert "No marker here." in content
    assert "VibeSec" in content


def test_cmd_scan_path_not_exists(tmp_path, capsys):
    missing_path = tmp_path / "does_not_exist"
    with pytest.raises(SystemExit) as excinfo:
        cmd_scan(ScanArgs(missing_path))

    assert excinfo.value.code == 1
    assert "Error: Path does not exist:" in capsys.readouterr().err


def test_cmd_scan_skips_symlink_path(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text("print('target')\n")
    link = tmp_path / "linked.py"
    _create_symlink(target, link)

    assert cmd_scan(ScanArgs(link)) == 0
    assert "Skipping symlink path:" in capsys.readouterr().out

    # We will simulate the target_file resolving outside the project_root.
    # We can do this by patching `Path.resolve` just for this test, or creating a symlink.
    pass


def test_cmd_init_path_traversal_checklist(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    # checklist가 symlink되어 외부를 가리키면?
    checklist_link = tmp_path / "VIBESEC_CHECKLIST.md"
    outside_dir = tmp_path.parent / "outside"
    outside_dir.mkdir(exist_ok=True)
    outside_file = outside_dir / "outside.md"
    outside_file.touch()

    _create_symlink(outside_file, checklist_link)

    with pytest.raises(SystemExit) as exc:
        cmd_init(Args(tool="cursor"))

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "escapes the project root" in err
    assert "💡 Hint: Ensure" in err


def test_cmd_init_path_traversal_target_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    # .cursor/rules/vibesec.md symlinked to outside
    rules_dir = tmp_path / ".cursor" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    outside_dir = tmp_path.parent / "outside2"
    outside_dir.mkdir(exist_ok=True)
    outside_file = outside_dir / "vibesec.md"
    outside_file.touch()

    target_link = rules_dir / "vibesec.md"
    _create_symlink(outside_file, target_link)

    with pytest.raises(SystemExit) as exc:
        cmd_init(Args(tool="cursor"))

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "escapes the project root" in err
    assert "💡 Hint: Ensure" in err


from scanner.cli.vibesec import cmd_hook


class HookArgs:
    pass


def test_cmd_hook_no_git_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cmd_hook(HookArgs()) == 1
    assert "Not a git repository" in capsys.readouterr().err


def test_cmd_hook_success(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    assert cmd_hook(HookArgs()) == 0

    hook_file = git_dir / "hooks" / "pre-commit"
    assert hook_file.exists()
    assert "vibesec scan ." in hook_file.read_text()
    import stat

    assert hook_file.stat().st_mode & stat.S_IEXEC

    assert "pre-commit hook installed successfully" in capsys.readouterr().out


def test_cmd_hook_path_traversal(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    # hooks symlinked to outside
    outside_dir = tmp_path.parent / "outside_hooks"
    outside_dir.mkdir(exist_ok=True)

    hooks_link = git_dir / "hooks"
    _create_symlink(outside_dir, hooks_link, target_is_directory=True)

    assert cmd_hook(HookArgs()) == 1
    err = capsys.readouterr().err
    assert "escapes the project root" in err
    assert "💡 Hint: Ensure" in err


def test_cmd_hook_remove_symlink(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir()

    dummy = tmp_path / "dummy_hook"
    dummy.touch()

    hook_link = hooks_dir / "pre-commit"
    _create_symlink(dummy, hook_link)

    assert cmd_hook(HookArgs()) == 0
    assert not hook_link.is_symlink()


from scanner.cli.vibesec import _collect_files, _scan_file


def test_collect_files_oserror_on_scandir(tmp_path):
    import os

    original_scandir = os.scandir

    def mock_scandir(path):
        raise PermissionError("Mock permission error")

    with patch("os.scandir", mock_scandir):
        files = list(_collect_files(tmp_path))
        assert files == []


def test_collect_files_oserror_on_entry(tmp_path):
    import os

    original_scandir = os.scandir

    class MockEntry:
        def __init__(self, is_dir_val, is_file_val, is_symlink_val):
            self._is_dir = is_dir_val
            self._is_file = is_file_val
            self._is_symlink = is_symlink_val
            self.name = "mock"
            self.path = str(tmp_path / "mock")

        def is_dir(self, follow_symlinks=False):
            if self._is_dir:
                raise OSError("Mock OS Error")
            return False

        def is_file(self, follow_symlinks=False):
            return self._is_file

        def is_symlink(self):
            return self._is_symlink

    def mock_scandir(path):
        class MockIt:
            def __enter__(self):
                return [MockEntry(True, False, False)]

            def __exit__(self, *args):
                pass

        return MockIt()

    with patch("os.scandir", mock_scandir):
        files = list(_collect_files(tmp_path))
        assert files == []


def test_scan_file_lstat_oserror(tmp_path):
    import os

    test_file = tmp_path / "test.ts"

    with patch("os.lstat", side_effect=OSError("Mock OS Error")):
        assert _scan_file(test_file, tmp_path) == []


def test_scan_file_large_file(tmp_path):
    import os

    test_file = tmp_path / "large.ts"

    class MockStat:
        st_mode = 0o100644  # Regular file
        st_size = 20 * 1024 * 1024  # 20MB

    with patch("os.lstat", return_value=MockStat()):
        assert _scan_file(test_file, tmp_path) == []


def test_scan_file_not_regular(tmp_path):
    import os
    import stat

    test_file = tmp_path / "fifo"

    class MockStat:
        st_mode = stat.S_IFIFO  # FIFO pipe
        st_size = 100

    with patch("os.lstat", return_value=MockStat()):
        assert _scan_file(test_file, tmp_path) == []


import sys

from scanner.cli.vibesec import cmd_review, main


class ReviewArgs:
    def __init__(self, stack=None, db=None, payments=None):
        self.stack = stack
        self.db = db
        self.payments = payments


def test_cmd_review_all_flags(capsys):
    cmd_review(ReviewArgs(stack="nextjs-supabase", db="supabase", payments="stripe"))
    out = capsys.readouterr().out
    assert "Next.js application" in out
    assert "Supabase RLS" in out
    assert "Stripe" in out


def test_cmd_review_firebase(capsys):
    cmd_review(ReviewArgs(stack="nextjs-firebase", db="firebase"))
    out = capsys.readouterr().out
    assert "Firebase Rules" in out
    assert "Next.js application" in out


def test_main_init(monkeypatch, capsys):
    test_args = ["vibesec", "init", "--tool", "cursor"]
    monkeypatch.setattr(sys, "argv", test_args)
    # mock cmd_init to just print and return
    with patch("scanner.cli.vibesec.cmd_init") as mock_init:
        main()
        mock_init.assert_called_once()


def test_main_scan(monkeypatch):
    test_args = ["vibesec", "scan", "."]
    monkeypatch.setattr(sys, "argv", test_args)
    with patch("scanner.cli.vibesec.cmd_scan", return_value=0) as mock_scan:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        mock_scan.assert_called_once()


def test_main_review(monkeypatch):
    test_args = ["vibesec", "review", "--stack", "nextjs"]
    monkeypatch.setattr(sys, "argv", test_args)
    with patch("scanner.cli.vibesec.cmd_review") as mock_review:
        main()
        mock_review.assert_called_once()


def test_main_hook(monkeypatch):
    test_args = ["vibesec", "hook"]
    monkeypatch.setattr(sys, "argv", test_args)
    with patch("scanner.cli.vibesec.cmd_hook", return_value=0) as mock_hook:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        mock_hook.assert_called_once()


def test_main_no_args(monkeypatch, capsys):
    test_args = ["vibesec"]
    monkeypatch.setattr(sys, "argv", test_args)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert "usage: vibesec" in capsys.readouterr().out


def test_cmd_scan_actual_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    test_file = tmp_path / "unsafe.ts"
    test_file.write_text("const key = MOCK_SECRET_KEY;\n")

    with patch("scanner.cli.vibesec.SCAN_RULES", MOCK_RULES):
        assert cmd_scan(ScanArgs(tmp_path)) == 1


def test_cmd_scan_actual_run_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    test_file = tmp_path / "safe.ts"
    test_file.write_text("console.log('safe');\n")

    with patch("scanner.cli.vibesec.SCAN_RULES", MOCK_RULES):
        assert cmd_scan(ScanArgs(test_file)) == 0


def test_scan_file_empty_rules(tmp_path):
    test_file = tmp_path / "safe.txt"
    test_file.write_text("hello\n")
    with patch("scanner.cli.vibesec.SCAN_RULES", []):
        assert _scan_file(test_file, tmp_path) == []


import runpy


def test_if_name_main():
    import sys
    from unittest.mock import patch

    original_argv = sys.argv
    sys.argv = ["vibesec", "--help"]

    try:
        with patch("sys.exit") as mock_exit:
            runpy.run_path("scanner/cli/vibesec.py", run_name="__main__")
            mock_exit.assert_called_with(0)
    finally:
        sys.argv = original_argv
