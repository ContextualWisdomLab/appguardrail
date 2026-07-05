"""Tests for the pre-commit framework hook definition (.pre-commit-hooks.yaml).

Stdlib only — no pyyaml dependency. We assert on the raw text so the test
stays dependency-free and matches the no-new-deps policy.
"""

from pathlib import Path

HOOKS_FILE = Path(__file__).resolve().parent.parent / ".pre-commit-hooks.yaml"


def test_precommit_hooks_file_exists():
    assert HOOKS_FILE.is_file(), f"{HOOKS_FILE} should exist for pre-commit framework support"


def test_precommit_hooks_declares_appguardrail_hook():
    text = HOOKS_FILE.read_text(encoding="utf-8")
    assert "id: appguardrail" in text
    assert "entry: appguardrail scan" in text
    assert "language: python" in text
    assert "pass_filenames: false" in text
