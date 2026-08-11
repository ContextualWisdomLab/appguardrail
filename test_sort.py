from appguardrail_core.findings import finding_sort_key

finding = {
    "severity": [],
    "category": {},
    "rule_id": [],
    "context": {},
}
print(finding_sort_key(finding))
