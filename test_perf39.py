import time
from appguardrail_core.findings import _SEVERITY_ORDER, SEVERITIES

def orig(finding):
    sev = finding.get("severity")
    if type(sev) is not str or sev not in _SEVERITY_ORDER:
        try:
            sev = str(sev or "INFO").upper()
        except Exception:
            sev = "INFO"

    cat = finding.get("category")
    if type(cat) is not str or not cat:
        try:
            cat = str(cat or "misconfig")
        except Exception:
            cat = "misconfig"

    rule = finding.get("rule_id")
    if type(rule) is not str or not rule:
        try:
            rule = str(rule or "unknown-rule")
        except Exception:
            rule = "unknown-rule"

    return (
        _SEVERITY_ORDER.get(sev, len(SEVERITIES)),
        cat,
        rule,
    )

def fast(finding):
    sev = finding.get("severity")
    idx = _SEVERITY_ORDER.get(sev) if type(sev) is str else None
    if idx is None:
        try:
            sev = str(sev or "INFO").upper()
            idx = _SEVERITY_ORDER.get(sev, len(SEVERITIES))
        except Exception:
            idx = len(SEVERITIES)

    cat = finding.get("category")
    if type(cat) is not str or not cat:
        try:
            cat = str(cat or "misconfig")
        except Exception:
            cat = "misconfig"

    rule = finding.get("rule_id")
    if type(rule) is not str or not rule:
        try:
            rule = str(rule or "unknown-rule")
        except Exception:
            rule = "unknown-rule"

    return (idx, cat, rule)

def test_perf():
    f = {"severity": "HIGH", "category": "secrets", "rule_id": "test-rule"}
    start = time.time()
    for _ in range(1000000):
        orig(f)
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(1000000):
        fast(f)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
