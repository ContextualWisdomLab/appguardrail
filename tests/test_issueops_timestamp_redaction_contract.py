"""Regression tests for allocation-efficient timestamp redaction semantics."""

import pytest

from appguardrail_core import issueops

_SPLITLINES_SEPARATORS = (
    "\n",
    "\r",
    "\r\n",
    "\v",
    "\f",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x85",
    "\u2028",
    "\u2029",
)
_TIMESTAMP = "2026-08-03T01:02:03.456Z "


@pytest.mark.parametrize("separator", _SPLITLINES_SEPARATORS)
def test_redact_handles_every_separator_recognized_by_splitlines(separator: str):
    """Timestamp removal must work after every Python line separator."""
    log = f"{_TIMESTAMP}first{separator}{_TIMESTAMP}second"

    assert issueops.redact(log) == "first\nsecond"


@pytest.mark.parametrize("separator", _SPLITLINES_SEPARATORS)
def test_redact_preserves_splitlines_trailing_separator_behavior(separator: str):
    """Joining split lines drops exactly one terminal line separator."""
    assert issueops.redact(f"first{separator}") == "first"
    assert issueops.redact(f"first{separator}{separator}") == "first\n"


def test_redact_preserves_non_newline_whitespace_after_timestamp():
    """Whole-string matching must retain per-line whitespace semantics."""
    assert issueops.redact(f"{_TIMESTAMP}\u00a0message") == "message"
