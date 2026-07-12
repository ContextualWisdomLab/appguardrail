"""Tests for the pre-commit framework integration (.pre-commit-hooks.yaml)."""

from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / ".pre-commit-hooks.yaml"


def test_hooks_file_exists_and_defines_appguardrail():
    text = HOOKS.read_text(encoding="utf-8")
    assert "- id: appguardrail" in text
    # entry must reference a real CLI invocation (console script + real subcommand)
    assert "entry: appguardrail scan ." in text
    assert "language: python" in text
    # scan takes a path, not per-file args from pre-commit
    assert "pass_filenames: false" in text
    assert "always_run: true" in text


def test_no_nonexistent_flags_referenced():
    # Guard: only flags that exist on develop may appear here.
    text = HOOKS.read_text(encoding="utf-8")
    assert "--diff" not in text  # not merged yet (#210)
