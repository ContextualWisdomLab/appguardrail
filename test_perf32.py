import time
from appguardrail_core.findings import _SEVERITY_ORDER, SEVERITIES

# In `appguardrail_core/findings.py`, `_SEVERITY_ORDER` is a static mapping of severities to integers.
# Calling `{sev for sev, order in _SEVERITY_ORDER.items() if order <= idx}` recomputes the set every time.
# Can we cache the sets entirely since `_SEVERITY_ORDER` is small and static?

_CACHE = {
    sev: {s for s, order in _SEVERITY_ORDER.items() if order <= _SEVERITY_ORDER[sev]}
    for sev in SEVERITIES
}

def ultra_fast_severities_at_or_above(min_severity: str) -> set[str]:
    # Return a copy to prevent mutation, though usually set operations are done
    sev = str(min_severity).upper()
    s = _CACHE.get(sev)
    if s is not None:
        return set(s)
    return set()

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
        ultra_fast_severities_at_or_above("HIGH")
    print(f"Ultra Fast: {time.time() - start:.4f}s")

test_perf()
