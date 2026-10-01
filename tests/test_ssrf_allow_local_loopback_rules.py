"""Source-derived regressions for hostname-unbound loopback SSRF exceptions."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-ssrf-allow-local-unbound-loopback"
_SOURCE_REPOSITORY = "ContextualWisdomLab/EgressWeave"
_VULNERABLE_HEAD_SHA = "271a9bb95d2a6274065e3e5535afbb880dd27a55"
_VULNERABLE_BLOB_SHA = "dc5bd8167593167a622de25d27e0f734b8d3eb5a"
_FIXED_HEAD_SHA = "81fc0a34cff7e8c90e3f0247342c0c8ee7de3d86"
_FIXED_BLOB_SHA = "7295c7cbf17c5d2b06dd7f77430e6674d2f25320"

_VULNERABLE_SOURCE = '''
import ipaddress

def _validate_global_address(
    address: str, policy: EgressPolicy, *, hostname: str | None = None
) -> str:
    try:
        ip_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from exc

    is_allowed_local = False
    if policy.allow_local:
        if ip_address.is_loopback:
            is_allowed_local = True
        elif hostname and _is_allowlisted_local_host(hostname, policy):
            is_allowed_local = True

    if not is_allowed_local:
        if (
            ip_address.is_private
            or ip_address.is_loopback
            or ip_address.is_link_local
            or not ip_address.is_global
        ):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    return str(ip_address)
'''

_FIXED_SOURCE = '''
import ipaddress

def _validate_global_address(
    address: str, policy: EgressPolicy, *, hostname: str | None = None
) -> str:
    ip_address = ipaddress.ip_address(address)
    if hostname and _is_local_dev_host(hostname):
        if not policy.allow_local or not ip_address.is_loopback:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        return str(ip_address)
    if hostname and _is_allowlisted_local_host(hostname, policy):
        if not (ip_address.is_loopback or _is_private_local_address(ip_address)):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        return str(ip_address)
    if (
        ip_address.is_private
        or ip_address.is_loopback
        or ip_address.is_link_local
        or not ip_address.is_global
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    return str(ip_address)
'''

_HOST_BOUND_BOOLEAN_SOURCE = '''
def _validate_global_address(address, policy, *, hostname=None):
    ip_address = ipaddress.ip_address(address)
    is_allowed_local = False
    if policy.allow_local and hostname and _is_local_dev_host(hostname):
        if ip_address.is_loopback:
            is_allowed_local = True
    if not is_allowed_local and not ip_address.is_global:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    return str(ip_address)
'''

_NON_SSRF_SOURCE = '''
def render_network_badge(ip_address, policy):
    is_allowed_local = False
    if policy.allow_local:
        if ip_address.is_loopback:
            is_allowed_local = True
    return "local" if is_allowed_local else "remote"
'''


def _rule() -> dict:
    """Return the packaged rule for this source-derived SSRF weakness family."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Run the production scanner and isolate this detector's findings."""
    source_file = tmp_path / "validation.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_pins_egressweave_source_objects() -> None:
    """Bind the source replay to the vulnerable and reviewed fixed Git objects."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/EgressWeave"
    assert _VULNERABLE_HEAD_SHA == "271a9bb95d2a6274065e3e5535afbb880dd27a55"
    assert _VULNERABLE_BLOB_SHA == "dc5bd8167593167a622de25d27e0f734b8d3eb5a"
    assert _FIXED_HEAD_SHA == "81fc0a34cff7e8c90e3f0247342c0c8ee7de3d86"
    assert _FIXED_BLOB_SHA == "7295c7cbf17c5d2b06dd7f77430e6674d2f25320"


def test_packaged_rule_detects_hostname_unbound_loopback_exception() -> None:
    """Detect `allow_local` granting loopback before original-hostname binding."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_packaged_rule_declares_parser_safe_prefilter() -> None:
    """Skip the multiline detector outside the exact address-validation contract."""
    assert _rule()["required_substrings"] == (
        "def _validate_global_address",
        "policy.allow_local",
        "ip_address.is_loopback",
        "is_allowed_local = True",
    )


def test_packaged_rule_ignores_reviewed_hostname_bound_repair() -> None:
    """Keep the reviewed EgressWeave repair negative."""
    assert not _rule()["pattern"].search(_FIXED_SOURCE)


def test_packaged_rule_ignores_host_bound_boolean_variant() -> None:
    """Allow a loopback exception only after an explicit hostname condition."""
    assert not _rule()["pattern"].search(_HOST_BOUND_BOOLEAN_SOURCE)


def test_packaged_rule_ignores_non_ssrf_loopback_display_logic() -> None:
    """Require the global-address validator rather than generic loopback logic."""
    assert not _rule()["pattern"].search(_NON_SSRF_SOURCE)


def test_scan_file_emits_normalized_ssrf_finding(tmp_path: Path) -> None:
    """Exercise the exact production scanner on the vulnerable source replay."""
    findings = _scan(_VULNERABLE_SOURCE, tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    expected_line = _VULNERABLE_SOURCE.splitlines().index("def _validate_global_address(") + 1
    assert finding["line"] == expected_line
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "high"
    assert finding["source"] == "appguardrail-rule"
    assert "CWE-918 - Server-Side Request Forgery (SSRF)" in finding["cwe"]


def test_scan_file_keeps_reviewed_fix_clean(tmp_path: Path) -> None:
    """Keep the source-derived fixed oracle clean through production scanning."""
    assert _scan(_FIXED_SOURCE, tmp_path) == []
