"""Regression coverage for credential-only HTTP authorities with no hostname."""

import pytest

from appguardrail_core.controlplane import _is_safe_url as controlplane_is_safe_url
from scanner.cli.appguardrail import _is_safe_url as cli_is_safe_url


@pytest.mark.parametrize(
    "validator",
    [controlplane_is_safe_url, cli_is_safe_url],
    ids=["controlplane", "cli"],
)
@pytest.mark.parametrize(
    "url",
    ["http://user:pass@", "http://user@/"],
    ids=["userinfo-only", "userinfo-path-separator"],
)
def test_userinfo_only_authority_is_rejected_as_hostless(validator, url: str) -> None:
    """Credentials or a trailing path separator never substitute for a hostname."""
    assert validator(url) is False
