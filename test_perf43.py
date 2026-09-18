import time
from appguardrail_core.findings import _SEVERITY_ORDER

_SEV_CACHE = {
    sev: {s for s, order in _SEVERITY_ORDER.items() if order <= _SEVERITY_ORDER[sev]}
    for sev in _SEVERITY_ORDER
}

def severities_at_or_above_orig(min_severity: str) -> set[str]:
    idx = _SEVERITY_ORDER.get(str(min_severity).upper())
    if idx is None:
        return set()
    return {sev for sev, order in _SEVERITY_ORDER.items() if order <= idx}

def severities_at_or_above_fast(min_severity: str) -> set[str]:
    # ⚡ Bolt: Fast O(1) dictionary lookup replacing O(N) generator evaluation
    # for static severity boundaries
    s = _SEV_CACHE.get(str(min_severity).upper())
    return set(s) if s is not None else set()
