"""Tests for `appguardrail scan --diff` git-diff-limited scanning."""

import shutil
import subprocess

import pytest

from scanner.cli.appguardrail import cmd_scan


class ScanArgs:
    """Minimal args stand-in matching the scan subparser defaults."""

    def __init__(self, path, diff=None):
        self.path = str(path)
        self.trivy = False
        self.external = "off"
        self.bandit = False
        self.ruff = False
        self.semgrep = False
        self.semgrep_config = None
        self.zap_baseline = None
        self.codegraph = False
        self.diff = diff


def _git(repo, *args):
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _init_repo(repo):
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")


def test_diff_scans_only_changed_files(tmp_path, capsys):
    if not shutil.which("git"):
        pytest.skip("git is not available")

    _init_repo(tmp_path)

    # First commit: a clean file that also carries a secret, but stays unchanged.
    committed = tmp_path / "committed.py"
    committed.write_text("const key = MOCK_SECRET_KEY;\n")
    _git(tmp_path, "add", "committed.py")
    _git(tmp_path, "commit", "-m", "initial")

    # Second commit: the only file that changed versus HEAD~1.
    changed = tmp_path / "changed.py"
    changed.write_text("const key = MOCK_SECRET_KEY;\n")
    _git(tmp_path, "add", "changed.py")
    _git(tmp_path, "commit", "-m", "add changed")

    cmd_scan(ScanArgs(tmp_path, diff="HEAD~1"))
    out = capsys.readouterr().out

    # Two files exist, but only the changed one is collected AND scanned.
    assert "🔀 Diff mode (HEAD~1): 1 changed file(s) to scan" in out
    assert "Scanned 1 file" in out


def test_diff_with_no_changes_scans_nothing(tmp_path, capsys):
    if not shutil.which("git"):
        pytest.skip("git is not available")

    _init_repo(tmp_path)
    committed = tmp_path / "committed.py"
    committed.write_text("const key = MOCK_SECRET_KEY;\n")
    _git(tmp_path, "add", "committed.py")
    _git(tmp_path, "commit", "-m", "initial")

    result = cmd_scan(ScanArgs(tmp_path, diff="HEAD"))
    out = capsys.readouterr().out

    assert "🔀 Diff mode (HEAD): 0 changed file(s) to scan" in out
    assert "Scanned 0 files" in out
    # No files scanned → same "nothing to scan" exit status as an empty dir.
    assert result == 1


def test_diff_in_non_git_dir_falls_back_to_full_scan(tmp_path, capsys):
    # No git repo here — diff should warn and scan everything.
    (tmp_path / "app.py").write_text("const key = MOCK_SECRET_KEY;\n")

    cmd_scan(ScanArgs(tmp_path, diff="HEAD~1"))
    captured = capsys.readouterr()

    assert "scanning all files" in captured.err
    assert "🔀 Diff mode" not in captured.out
    assert "Scanned 1 file" in captured.out
