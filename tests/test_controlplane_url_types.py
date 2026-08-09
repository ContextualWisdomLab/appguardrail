"""Regression tests for webhook URL type validation."""

from __future__ import annotations

import pytest

from appguardrail_core.controlplane import _is_safe_url


@pytest.mark.parametrize("value", [123, True, {}, []])
def test_is_safe_url_rejects_non_string_values(value: object) -> None:
    """Malformed JSON values must fail closed instead of raising server errors."""
    assert _is_safe_url(value) is False
