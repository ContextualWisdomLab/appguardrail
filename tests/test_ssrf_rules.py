"""Regression tests for stored SSRF detection in the packaged rule engine."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-stored-ssrf-webhook-url"


def _rule():
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _vulnerable_source():
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            f'    {sink}(conn, org, (body or {{}}).get("url"))',
            "",
        ]
    )


def _unvalidated_variable_source(variable="webhook_url"):
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            f'    {variable} = (body or {{}}).get("url")',
            f"    {sink}(conn, org, {variable})",
            "",
        ]
    )


def _ignored_validation_result_source():
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    target = (body or {}).get("url")',
            "    _is_safe_url(target)",
            f"    {sink}(conn, org, target)",
            "",
        ]
    )


def _non_enforcing_guard_source():
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    target = (body or {}).get("url")',
            "    if not _is_safe_url(target):",
            '        log.warning("unsafe webhook url")',
            f"    {sink}(conn, org, target)",
            "",
        ]
    )


def _positive_guard_source():
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    target = (body or {}).get("url")',
            "    if _is_safe_url(target):",
            f"        {sink}(conn, org, target)",
            "",
        ]
    )


def _safe_source():
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    webhook_url = (body or {}).get("url")',
            "    if webhook_url and not _is_safe_url(webhook_url):",
            "        raise ValueError(\"unsafe webhook url\")",
            f"    {sink}(conn, org, webhook_url)",
            "",
        ]
    )


def _scan_rule_findings(tmp_path, source):
    source_file = tmp_path / "webhook.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_packaged_rule_matches_direct_request_url_persistence():
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_vulnerable_source())


def test_packaged_rule_matches_unvalidated_variable_persistence():
    assert _rule()["pattern"].search(_unvalidated_variable_source())


def test_packaged_rule_does_not_depend_on_url_variable_name():
    assert _rule()["pattern"].search(_unvalidated_variable_source("target"))


def test_packaged_rule_does_not_treat_ignored_validator_result_as_safe():
    assert _rule()["pattern"].search(_ignored_validation_result_source())


def test_packaged_rule_matches_non_enforcing_validation_guard():
    assert _rule()["pattern"].search(_non_enforcing_guard_source())


def test_packaged_rule_ignores_positive_guarded_persistence():
    assert not _rule()["pattern"].search(_positive_guard_source())


def test_packaged_rule_ignores_fail_closed_guarded_persistence():
    assert not _rule()["pattern"].search(_safe_source())


def test_scan_file_emits_stored_ssrf_finding(tmp_path):
    matches = _scan_rule_findings(tmp_path, _vulnerable_source())

    assert len(matches) == 1
    finding = matches[0]
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["file"] == "webhook.py"
    assert finding["line"] == 2
    assert finding["category"] == "ssrf"
    assert finding["cwe"] == ("CWE-918 - Server-Side Request Forgery",)
    assert finding["owasp"] == ("OWASP A10:2021 - Server-Side Request Forgery",)
    assert "destination" in finding["remediation"].lower()


def test_scan_file_emits_stored_ssrf_finding_for_variable_flow(tmp_path):
    matches = _scan_rule_findings(tmp_path, _unvalidated_variable_source())

    assert len(matches) == 1
    assert matches[0]["line"] == 2


def test_scan_file_emits_finding_when_validator_result_is_ignored(tmp_path):
    matches = _scan_rule_findings(tmp_path, _ignored_validation_result_source())

    assert len(matches) == 1
    assert matches[0]["line"] == 2


def test_scan_file_emits_finding_for_non_enforcing_guard(tmp_path):
    matches = _scan_rule_findings(tmp_path, _non_enforcing_guard_source())

    assert len(matches) == 1
    assert matches[0]["line"] == 2


def test_scan_file_does_not_flag_validated_path(tmp_path):
    assert not _scan_rule_findings(tmp_path, _safe_source())
