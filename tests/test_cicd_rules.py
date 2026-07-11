"""Coverage tests for the CI/CD security rules (cicd.yml)."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rid):
    assert rid in _BY_ID, f"rule not loaded: {rid}"
    return _BY_ID[rid]


CASES = {
    "github-action-mutable-ref": (
        ["uses: actions/checkout@main", "  uses: foo/bar@master"],
        ["uses: actions/checkout@v4", "uses: actions/checkout@a1b2c3d4e5f6", "uses: ./local"],
    ),
    "github-actions-pull-request-target": (
        ["  pull_request_target:", "on:\n  pull_request_target:\n"],
        ["  pull_request:", "  push:"],
    ),
    "github-actions-script-injection": (
        ["run: echo ${{ github.event.issue.title }}", "${{ github.event.pull_request.body }}"],
        ["${{ github.event.number }}", "${{ secrets.TOKEN }}", "${{ github.sha }}"],
    ),
}


@pytest.mark.parametrize("rid", CASES.keys())
def test_cicd_rule_precision(rid):
    rule = _rule(rid)
    pos, neg = CASES[rid]
    for s in pos:
        assert rule["pattern"].search(s), f"{rid} should match: {s!r}"
    for s in neg:
        assert not rule["pattern"].search(s), f"{rid} false-positive: {s!r}"


def test_cicd_severities():
    assert _rule("github-actions-pull-request-target")["severity"] == "HIGH"
    assert _rule("github-actions-script-injection")["severity"] == "HIGH"
    assert _rule("github-action-mutable-ref")["severity"] == "WARNING"
