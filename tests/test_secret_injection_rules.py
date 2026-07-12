"""Coverage tests for the secret + injection rule batch (8 rules)."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


CASES = {
    "hardcoded-aws-access-key-id": (
        ["AKIAIOSFODNN7EXAMPLE", "ASIAY34FZKBOKMUTVV7A"],
        ["us-east-1", "AKIASHORT", "akiaiosfodnn7example"],
    ),
    "hardcoded-github-token": (
        ["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "github_pat_" + "a" * 62],
        ["ghpage", "ghp_tooshort123", "github.com/owner/repo"],
    ),
    "hardcoded-google-api-key": (
        # Assemble at runtime so repository secret scanning never sees a full key.
        ["AIza" + ("A" * 35)],
        ["AIzaLikePrefix", "projectId = 'my-project'"],
    ),
    "hardcoded-private-key-block": (
        ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"],
        ["-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"],
    ),
    "supabase-auth-admin-client-usage": (
        ["supabase.auth.admin.deleteUser(id)", "client.auth.admin.listUsers()"],
        ["supabase.auth.getUser()", "admin.auth().verifyIdToken(t)"],
    ),
    "insecure-random-security-token": (
        ["const token = Math.random().toString(36)", "let sessionId = Math.random()"],
        ["const delay = Math.random() * 1000", "crypto.randomBytes(32)"],
    ),
    "node-open-redirect-user-input": (
        ["res.redirect(req.query.url)", "res.redirect(302, req.body.next)"],
        ["res.redirect('/login')", "res.redirect(sanitize(req.query.url))"],
    ),
    "wildcard-postmessage-target": (
        ["window.postMessage(payload, '*')", 'iframe.postMessage(data, "*")'],
        ["el.postMessage(msg, 'https://trusted.com')", "worker.postMessage(data)"],
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
    assert _rule("hardcoded-aws-access-key-id")["severity"] == "CRITICAL"
    assert _rule("hardcoded-private-key-block")["severity"] == "CRITICAL"
    assert _rule("supabase-auth-admin-client-usage")["severity"] == "HIGH"
    assert _rule("wildcard-postmessage-target")["severity"] == "WARNING"
