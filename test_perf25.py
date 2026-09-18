import time
from appguardrail_core.rules import REFERENCE_CATEGORY_OVERRIDES

def orig(references, fallback):
    for reference in references:
        for prefix, category in REFERENCE_CATEGORY_OVERRIDES.items():
            if reference.startswith(prefix):
                return category
    return fallback

def fast(references, fallback):
    items = tuple(REFERENCE_CATEGORY_OVERRIDES.items())
    for reference in references:
        for prefix, category in items:
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
        fast(references, "default")
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
