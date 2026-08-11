from appguardrail_core.findings import normalize_finding, severity_counts, finding_sort_key, is_deploy_blocking

def test_unhashable():
    finding = {"severity": ["HIGH"]}
    normalize_finding(finding)

test_unhashable()
