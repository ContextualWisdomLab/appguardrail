from appguardrail_core.findings import normalize_finding

def test_unhashable():
    finding = {"severity": ["HIGH"]}
    normalize_finding(finding)
