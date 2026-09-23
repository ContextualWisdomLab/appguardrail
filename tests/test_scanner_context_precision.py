"""Regression tests for scanner context and deferred-security marker precision."""

from scanner.cli.appguardrail import SCAN_RULES, _finding_context


def _todo_skip_auth_pattern():
    """Return the canonical deferred-security marker pattern."""
    return next(rule["pattern"] for rule in SCAN_RULES if rule["id"] == "todo-skip-auth")


def test_colocated_test_suffixes_are_test_context():
    """Colocated test naming must not become deploy-blocking application context."""
    assert _finding_context("src/widget.test.ts") == "test"
    assert _finding_context("src/widget.integration.test.ts") == "test"
    assert _finding_context("packages/core/src/widget.test.mjs") == "test"


def test_todo_skip_auth_requires_lexical_marker_tokens():
    """Ordinary words containing marker/security substrings must not match the rule."""
    pattern = _todo_skip_auth_pattern()
    assert pattern.search("attempt cannot create authority") is None
    assert pattern.search("attempt preserves authentication authority") is None


def test_todo_skip_auth_keeps_real_deferred_security_marker():
    """A real deferred-auth comment remains detectable."""
    pattern = _todo_skip_auth_pattern()
    assert pattern.search("// TODO: skip auth check before release") is not None
