"""Coverage tests for the Kubernetes manifest misconfiguration rules."""

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def test_k8s_privileged_container():
    r = _rule("k8s-privileged-container")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("        securityContext:\n          privileged: true")
    assert r["pattern"].search("privileged:  true")
    # hardened config must NOT match
    assert not r["pattern"].search("          privileged: false")


def test_k8s_host_namespace_shared():
    r = _rule("k8s-host-namespace-shared")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("  hostNetwork: true")
    assert r["pattern"].search("  hostPID: true")
    assert r["pattern"].search("  hostIPC: true")
    assert not r["pattern"].search("  hostNetwork: false")


def test_k8s_allow_privilege_escalation():
    r = _rule("k8s-allow-privilege-escalation")
    assert r["severity"] == "WARNING"
    assert r["pattern"].search("          allowPrivilegeEscalation: true")
    assert not r["pattern"].search("          allowPrivilegeEscalation: false")


def test_k8s_run_as_non_root_disabled():
    r = _rule("k8s-run-as-non-root-disabled")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("          runAsNonRoot: false")
    assert not r["pattern"].search("          runAsNonRoot: true")


def test_k8s_run_as_root_user():
    r = _rule("k8s-run-as-root-user")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("          runAsUser: 0")
    assert r["pattern"].search("runAsUser: 0\n")
    # a non-root UID must NOT match
    assert not r["pattern"].search("          runAsUser: 1000")
