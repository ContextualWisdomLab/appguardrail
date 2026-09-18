import time
from appguardrail_core.findings import _SEVERITY_ORDER

def fast_severities_at_or_above(min_severity: str) -> set[str]:
    idx = _SEVERITY_ORDER.get(str(min_severity).upper())
    if idx is None:
        return set() # simplified for benchmark
    # Use pre-extracted items to avoid .items() generator overhead
    return {sev for sev, order in _SEVERITY_ORDER_ITEMS if order <= idx}

_SEVERITY_ORDER_ITEMS = tuple(_SEVERITY_ORDER.items())

def orig_severities_at_or_above(min_severity: str) -> set[str]:
    idx = _SEVERITY_ORDER.get(str(min_severity).upper())
    if idx is None:
        return set()
    return {sev for sev, order in _SEVERITY_ORDER.items() if order <= idx}

def test_perf():
    start = time.time()
    for _ in range(100000):
        orig_severities_at_or_above("HIGH")
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100000):
        fast_severities_at_or_above("HIGH")
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
