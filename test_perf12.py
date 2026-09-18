import time

def orig(components):
    seen, unique = set(), []
    for c in components:
        key = (c["name"], c.get("version", ""))
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique

def fast(components):
    # Using dict for insertion order preservation and O(1) deduplication
    unique_dict = {}
    for c in components:
        key = (c["name"], c.get("version", ""))
        if key not in unique_dict:
            unique_dict[key] = c
    return list(unique_dict.values())

def test_perf():
    components = [{"name": f"pkg_{i%1000}", "version": f"1.0.{i%10}"} for i in range(10000)]
    start = time.time()
    for _ in range(1000):
        orig(components)
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(1000):
        fast(components)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
