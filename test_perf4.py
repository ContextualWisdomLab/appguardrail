import time

_RULES_CACHE = {".py": [(1,2,3,4,5,6,7)] * 10}

def get_applicable_rules(ext):
    return _RULES_CACHE.get(ext, [])

def get_applicable_rules_orig(ext):
    if ext not in _RULES_CACHE:
        _RULES_CACHE[ext] = [(1,2,3,4,5,6,7)] * 10
    return _RULES_CACHE[ext]

start = time.time()
for _ in range(10000000):
    get_applicable_rules(".py")
print(f"dict.get: {time.time() - start:.4f}s")

start = time.time()
for _ in range(10000000):
    get_applicable_rules_orig(".py")
print(f"in dict: {time.time() - start:.4f}s")
