import time
from appguardrail_core.sbom import parse_package_lock

def orig(components):
    seen, unique = set(), []
    for c in components:
        key = (c["name"], c.get("version", ""))
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique

def fast(components):
    # Using dict for O(1) deduplication + implicit ordered insertion in python 3.7+
    # Avoids separate set and list structures
    return list({(c["name"], c.get("version", "")): c for c in components}.values())

def fast2(components):
    # Use dict.fromkeys but we need the actual object
    d = {}
    for c in components:
        d.setdefault((c["name"], c.get("version", "")), c)
    return list(d.values())

def test_perf():
    components = [{"name": f"pkg_{i%1000}", "version": f"1.0.{i%10}"} for i in range(100000)]
    start = time.time()
    for _ in range(100):
        orig(components)
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100):
        fast(components)
    print(f"Dict comp (reversed): {time.time() - start:.4f}s")
    # Dictionary comprehension replaces earlier entries if duplicates exist,
    # the original code kept the FIRST entry seen. So we need to use setdefault
    # or explicitly check.

    start = time.time()
    for _ in range(100):
        fast2(components)
    print(f"Setdefault: {time.time() - start:.4f}s")

test_perf()
