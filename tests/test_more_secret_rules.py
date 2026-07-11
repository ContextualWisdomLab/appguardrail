"""Precision tests for the additional provider secret detectors."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


CASES = {
    "hardcoded-slack-token": (
        [
            "xoxb-1234567890-ABCDefgh1234",
            'token = "xoxp-0987654321-abcdef-value"',
        ],
        ["xoxq-1234567890", "xoxb-short", "box-1234567890abc"],
    ),
    "hardcoded-slack-webhook-url": (
        [
            "https://hooks.slack.com/services/T00000000/B00000000/" + "X" * 24,
            "https://hooks.slack.com/services/T1A2B3C4D/B5E6F7G8H/abcDEF123456",
        ],
        [
            "https://hooks.slack.com/services/",
            "https://example.com/services/T0/B0/xxx",
        ],
    ),
    "hardcoded-twilio-credential": (
        ["AC" + "a" * 32, "SK" + "0123456789abcdef0123456789abcdef"],
        ["ACfoo", "SK" + "g" * 32, "AC" + "a" * 31, "ACCOUNT_NAME_HERE"],
    ),
    "hardcoded-sendgrid-api-key": (
        ["SG." + "a" * 22 + "." + "b" * 43, "SG.Ab3_-DeFgHiJkLmNoPqRsT." + "x" * 43],
        ["SG.short.key", "SG." + "a" * 22 + "." + "b" * 10],
    ),
    "hardcoded-npm-token": (
        [
            "npm_" + "a" * 36,
            "//registry.npmjs.org/:_authToken=npm_"
            + "AbCdEf1234567890AbCdEf1234567890AbCd",
        ],
        ["npm_short", "npm_" + "a" * 35, "npm install foo"],
    ),
    "hardcoded-pypi-token": (
        ["pypi-AgEIcHlwaS" + "a" * 60, "pypi-AgEIcHlwaS" + "Ab3_-" * 11],
        ["pypi-token", "pypi-AgEIcHlwaS" + "a" * 10],
    ),
}


@pytest.mark.parametrize("rule_id", CASES.keys())
def test_rule_precision(rule_id):
    rule = _rule(rule_id)
    positives, negatives = CASES[rule_id]
    for s in positives:
        assert rule["pattern"].search(s), f"{rule_id} should match: {s!r}"
    for s in negatives:
        assert not rule["pattern"].search(s), f"{rule_id} false-positive on: {s!r}"


def test_severities():
    assert _rule("hardcoded-slack-token")["severity"] == "CRITICAL"
    assert _rule("hardcoded-slack-webhook-url")["severity"] == "HIGH"
    assert _rule("hardcoded-twilio-credential")["severity"] == "CRITICAL"
    assert _rule("hardcoded-sendgrid-api-key")["severity"] == "CRITICAL"
    assert _rule("hardcoded-npm-token")["severity"] == "CRITICAL"
    assert _rule("hardcoded-pypi-token")["severity"] == "CRITICAL"
