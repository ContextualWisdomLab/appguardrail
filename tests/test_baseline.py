"""Tests for baseline diff mode (appguardrail_core.findings)."""

from appguardrail_core.findings import (
    finding_fingerprint,
    is_deploy_blocking,
    partition_new_findings,
)


def test_fingerprint_is_line_independent():
    a = {"rule_id": "r1", "file": "a.ts", "line": 10, "message": "m", "snippet": "code X"}
    moved = {**a, "line": 999}  # unrelated edit shifted the line
    assert finding_fingerprint(a) == finding_fingerprint(moved)


def test_fingerprint_tracks_content_and_location():
    base = {"rule_id": "r1", "file": "a.ts", "line": 1, "snippet": "code X"}
    assert finding_fingerprint(base) != finding_fingerprint({**base, "snippet": "code Y"})
    assert finding_fingerprint(base) != finding_fingerprint({**base, "file": "b.ts"})
    assert finding_fingerprint(base) != finding_fingerprint({**base, "rule_id": "r2"})


def test_fingerprint_falls_back_to_message_without_snippet():
    a = {"rule_id": "r1", "file": "a.ts", "message": "hello"}
    assert finding_fingerprint(a) == finding_fingerprint({**a, "line": 42})


def test_partition_splits_new_and_known():
    a = {"rule_id": "r1", "file": "a.ts", "line": 10, "snippet": "X"}
    a_moved = {**a, "line": 999}
    b = {"rule_id": "r2", "file": "b.ts", "line": 3, "snippet": "Y"}
    new, baselined = partition_new_findings([a_moved, b], baseline=[a])
    assert new == [b]
    assert baselined == [a_moved]


def test_baseline_suppresses_deploy_gate():
    # A blocking finding that already exists in the baseline should not gate.
    crit = {"severity": "CRITICAL", "rule_id": "secret", "file": "app.ts",
            "line": 5, "snippet": "sk_live_xxx", "context": "app-code"}
    assert is_deploy_blocking(crit) is True
    new, _ = partition_new_findings([{**crit, "line": 8}], baseline=[crit])
    assert new == []  # same finding, line moved -> suppressed -> gate clears
