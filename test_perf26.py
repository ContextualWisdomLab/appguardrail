import time
from appguardrail_core.rules import REFERENCE_CATEGORY_OVERRIDES

# This dictionary is static, we can extract its items outside the function
_REFERENCE_CATEGORY_OVERRIDES_ITEMS = tuple(REFERENCE_CATEGORY_OVERRIDES.items())

def fast2(references, fallback):
    for reference in references:
        for prefix, category in _REFERENCE_CATEGORY_OVERRIDES_ITEMS:
            if reference.startswith(prefix):
                return category
    return fallback

def orig(references, fallback):
    for reference in references:
        for prefix, category in REFERENCE_CATEGORY_OVERRIDES.items():
            if reference.startswith(prefix):
                return category
    return fallback

def test_perf():
    references = ["SOME 1", "SOME 2", "OWASP 3"] * 10
    start = time.time()
    for _ in range(100000):
        orig(references, "default")
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100000):
        fast2(references, "default")
    print(f"Fast2: {time.time() - start:.4f}s")

test_perf()
