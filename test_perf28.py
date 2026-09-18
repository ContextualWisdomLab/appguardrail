import time
from appguardrail_core.rules import REFERENCE_CATEGORY_OVERRIDES

# Optimize this
def _category_for_references(references: tuple[str, ...], fallback: str) -> str:
    """Prefer an authoritative public taxonomy over a rule-id heuristic."""
    for reference in references:
        for prefix, category in REFERENCE_CATEGORY_OVERRIDES.items():
            if reference.startswith(prefix):
                return category
    return fallback

_REFERENCE_CATEGORY_OVERRIDES_ITEMS = tuple(REFERENCE_CATEGORY_OVERRIDES.items())

def _category_for_references_fast(references: tuple[str, ...], fallback: str) -> str:
    for reference in references:
        for prefix, category in _REFERENCE_CATEGORY_OVERRIDES_ITEMS:
            if reference.startswith(prefix):
                return category
    return fallback

def test_perf():
    refs = ("https://some-link", "CWE-79", "OWASP A1")
    start = time.time()
    for _ in range(100000):
        _category_for_references(refs, "fallback")
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100000):
        _category_for_references_fast(refs, "fallback")
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
