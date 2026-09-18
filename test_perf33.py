import time
from appguardrail_core.findings import _SEVERITY_ORDER

def finding_sort_key_orig(finding):
    sev = finding.get("severity")
    if type(sev) is not str or sev not in _SEVERITY_ORDER:
        sev = "UNKNOWN"
    return (
        _SEVERITY_ORDER.get(sev, len(_SEVERITY_ORDER)),
        finding.get("category", "unknown"),
        finding.get("id", "unknown")
    )

def finding_sort_key_fast(finding):
    sev = finding.get("severity")
    # double lookup reduction + isinstance is faster than type()
    idx = _SEVERITY_ORDER.get(sev) if isinstance(sev, str) else None
    if idx is None:
        idx = len(_SEVERITY_ORDER)
    return (
        idx,
        finding.get("category", "unknown"),
        finding.get("id", "unknown")
    )

def test_perf():
    finding = {"severity": "HIGH", "category": "secrets", "id": "my-rule"}
    start = time.time()
    for _ in range(1000000):
        finding_sort_key_orig(finding)
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(1000000):
        finding_sort_key_fast(finding)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
