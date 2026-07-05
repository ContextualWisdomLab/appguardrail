"""Minimal, dependency-free checks for the repo-root composite GitHub Action.

The repository intentionally ships with no YAML dependency, so this test parses
``action.yml`` as text and asserts the load-bearing contract (composite runner,
expected inputs, and that it drives ``appguardrail scan``) with stdlib only.
"""

from pathlib import Path

ACTION_PATH = Path(__file__).resolve().parents[1] / "action.yml"


def _read_action() -> str:
    return ACTION_PATH.read_text(encoding="utf-8")


def test_action_file_exists():
    assert ACTION_PATH.is_file(), "action.yml must exist at the repository root"


def test_action_is_composite():
    text = _read_action()
    assert "using: \"composite\"" in text or "using: composite" in text


def test_action_declares_expected_inputs():
    text = _read_action()
    # Inputs are declared as two-space indented keys under `inputs:`.
    for key in ("path:", "sarif:", "args:"):
        assert f"  {key}" in text, f"action.yml is missing input '{key}'"


def test_action_has_path_default():
    text = _read_action()
    assert 'default: "."' in text, "the `path` input should default to '.'"


def test_action_runs_appguardrail_scan():
    text = _read_action()
    assert "appguardrail scan" in text
    assert "pip install" in text and "appguardrail" in text


def test_action_forwards_sarif_flag():
    text = _read_action()
    assert "--sarif" in text


def test_action_has_branding():
    text = _read_action()
    assert "branding:" in text
    assert "icon:" in text
    assert "color:" in text
