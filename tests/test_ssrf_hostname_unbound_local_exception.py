"""Regression tests for hostname-unbound local-address SSRF exceptions."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


_RULE_ID = "python-ssrf-hostname-unbound-local-address-exception"
_VULNERABLE_HEAD_SHA = "2d9dc094409bdc3574bcee6b9a5c52ea920b3936"
_VULNERABLE_BLOB_SHA = "caea83981a50407528ce3d45d16a5643d5ef0fbf"
_FIXED_HEAD_SHA = "81fc0a34cff7e8c90e3f0247342c0c8ee7de3d86"
_FIXED_BLOB_SHA = "7295c7cbf17c5d2b06dd7f77430e6674d2f25320"
_OWNER_MERGE_SHA = "6f337b67efd985bdfcb16646fa3726709bd2e17e"


def _rule():
    """Return the packaged hostname-unbound local-address exception rule."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1
    return matches[0]


def _vulnerable_source() -> str:
    """Replay the Issue #850 EgressWeave admission defect."""
    return """\
def _validate_global_address(
    address: str, policy: EgressPolicy, *, hostname: str | None = None
) -> str:
    \"\"\"Validate that an IP address is globally routable, or explicitly allowed.\"\"\"
    try:
        ip_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from exc

    is_allowed_local = False
    if policy.allow_local:
        if ip_address.is_loopback:
            is_allowed_local = True
        elif (
            hostname
            and _is_allowlisted_local_host(hostname, policy)
            and _is_private_local_address(ip_address)
        ):
            is_allowed_local = True

    if not is_allowed_local:
        if ip_address.is_private or ip_address.is_loopback:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    return str(ip_address)
"""


def _renamed_vulnerable_source() -> str:
    """Keep semantic identifiers flexible inside the bounded code shape."""
    return """\
def permits_egress_address(candidate, settings):
    admitted = False
    if settings.allow_local:
        if candidate.is_loopback:
            admitted = True
    return admitted
"""


def _fixed_source() -> str:
    """Replay the owner fix that binds each exception to the original hostname."""
    return """\
def _validate_global_address(
    address: str, policy: EgressPolicy, *, hostname: str | None = None
) -> str:
    \"\"\"Validate an address against hostname-bound local exceptions.\"\"\"
    ip_address = ipaddress.ip_address(address)
    if hostname and _is_local_dev_host(hostname):
        if not policy.allow_local or not ip_address.is_loopback:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        return str(ip_address)
    if hostname and _is_allowlisted_local_host(hostname, policy):
        if not (ip_address.is_loopback or _is_private_local_address(ip_address)):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        return str(ip_address)
    if ip_address.is_loopback or not ip_address.is_global:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    return str(ip_address)
"""


def _hostname_bound_source() -> str:
    """Admit loopback only after binding the exception to a local hostname."""
    return """\
def permits_local_address(hostname, ip_address, policy):
    admitted = False
    if policy.allow_local and hostname and _is_local_dev_host(hostname):
        if ip_address.is_loopback:
            admitted = True
    return admitted
"""


def _early_hostname_guard_source() -> str:
    """Admit loopback only after an earlier fail-closed hostname guard."""
    return """\
def validate_egress_address(hostname, ip_address, policy):
    if not _is_local_dev_host(hostname):
        return False
    admitted = False
    if policy.allow_local:
        if ip_address.is_loopback:
            admitted = True
    return admitted
"""


def _observation_only_source() -> str:
    """Observe local mode without using it as an address admission decision."""
    return """\
def report_local_address(ip_address, policy):
    if policy.allow_local:
        logger.info("local mode enabled")
    return ip_address.is_loopback
"""


@pytest.mark.parametrize("source", [_vulnerable_source(), _renamed_vulnerable_source()])
def test_packaged_rule_matches_hostname_unbound_local_exception(source: str) -> None:
    """Detect a global local-mode branch that directly admits loopback."""
    assert _rule()["pattern"].search(source)


@pytest.mark.parametrize(
    "source",
    [
        _fixed_source(),
        _hostname_bound_source(),
        _early_hostname_guard_source(),
        _observation_only_source(),
    ],
)
def test_packaged_rule_ignores_bound_and_non_admitting_flows(source: str) -> None:
    """Exclude hostname-bound, fail-closed, and observation-only flows."""
    assert not _rule()["pattern"].search(source)


def test_scan_file_emits_hostname_unbound_local_exception_finding(tmp_path) -> None:
    """Emit stable HIGH SSRF metadata through the production scanner."""
    source_file = tmp_path / "egress_policy.py"
    source_file.write_text(_vulnerable_source(), encoding="utf-8")

    findings = [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["category"] == "ssrf"
    assert findings[0]["cwe"] == ("CWE-918 - Server-Side Request Forgery",)
    assert "hostname" in findings[0]["message"].lower()
    assert "bind" in findings[0]["message"].lower()


def test_packaged_rule_declares_local_policy_prefilter() -> None:
    """Skip the bounded regex when no local-address exception is present."""
    assert _rule()["required_substrings"] == ("allow_local",)


def test_incident_corpus_pins_owner_source_and_fix() -> None:
    """Bind the regression to exact vulnerable, fixed, and merged owner evidence."""
    assert _VULNERABLE_HEAD_SHA == "2d9dc094409bdc3574bcee6b9a5c52ea920b3936"
    assert _VULNERABLE_BLOB_SHA == "caea83981a50407528ce3d45d16a5643d5ef0fbf"
    assert _FIXED_HEAD_SHA == "81fc0a34cff7e8c90e3f0247342c0c8ee7de3d86"
    assert _FIXED_BLOB_SHA == "7295c7cbf17c5d2b06dd7f77430e6674d2f25320"
    assert _OWNER_MERGE_SHA == "6f337b67efd985bdfcb16646fa3726709bd2e17e"
