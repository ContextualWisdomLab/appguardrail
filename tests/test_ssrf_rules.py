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


def test_packaged_rule_matches_direct_request_url_persistence():
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_vulnerable_source())


def test_packaged_rule_ignores_validated_url_persistence():
    assert not _rule()["pattern"].search(_safe_source())


def test_scan_file_emits_stored_ssrf_finding(tmp_path):
    source_file = tmp_path / "webhook.py"
    source_file.write_text(_vulnerable_source(), encoding="utf-8")

    matches = [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]

    assert len(matches) == 1
    assert matches[0]["severity"] == "HIGH"
    assert matches[0]["source"] == "appguardrail-rule"
    assert matches[0]["file"] == "webhook.py"
    assert matches[0]["line"] == 2


def test_scan_file_does_not_flag_validated_path(tmp_path):
    source_file = tmp_path / "webhook.py"
    source_file.write_text(_safe_source(), encoding="utf-8")

    assert _RULE_ID not in {
        finding["rule_id"] for finding in _scan_file(source_file, tmp_path)
    }
