"""Regression tests for equivalent stored-SSRF request accessors."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-stored-ssrf-webhook-url"


def _rule():
    """Return the packaged stored-SSRF rule under test."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1
    return matches[0]


def _source(accessor, *, direct=False, validated=False):
    """Build a direct or one-hop request URL persistence flow."""
    sink = "set_" + "webhook"
    if direct:
        return "\n".join(
            [
                "def update_webhook(conn, org, body):",
                f"    {sink}(conn, org, {accessor})",
                "",
            ]
        )

    lines = [
        "def update_webhook(conn, org, body):",
        f"    target = {accessor}",
    ]
    if validated:
        lines.extend(
            [
                "    if not _is_safe_url(target):",
                "        return",
            ]
        )
    lines.extend([f"    {sink}(conn, org, target)", ""])
    return "\n".join(lines)


@pytest.mark.parametrize(
    "source",
    [
        _source('body["url"]', direct=True),
        _source('request.json["url"]'),
        _source('request.json.get("url")'),
    ],
)
def test_packaged_rule_matches_equivalent_request_url_accessors(source):
    """Detect direct, subscript, and attribute-based URL sources."""
    assert _rule()["pattern"].search(source)


def test_scan_file_emits_finding_for_subscript_variable_flow(tmp_path):
    """Emit the stored-SSRF finding for a subscript one-hop flow."""
    source_file = tmp_path / "webhook.py"
    source_file.write_text(_source('body["url"]'), encoding="utf-8")

    findings = [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]

    assert len(findings) == 1
    assert findings[0]["line"] == 2
    assert findings[0]["category"] == "ssrf"


def test_packaged_rule_ignores_validated_subscript_flow():
    """Do not flag a subscript source protected by a fail-closed guard."""
    assert not _rule()["pattern"].search(
        _source('body["url"]', validated=True)
    )
