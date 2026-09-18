import time
from pathlib import Path

def get_applicable_rules(ext):
    if ext == ".py":
        return [(1, 2, 3, 4, 5, 6, 7)] * 20
    return []

# Simulate the loop logic
def original_loop(content, applicable_rules):
    for (rule_id, severity, message, finditer, include_paths, exclude_paths, required_substrings) in applicable_rules:
        pass

def fast_loop(content, applicable_rules):
    for (rule_id, severity, message, finditer, include_paths, exclude_paths, required_substrings) in applicable_rules:
        pass

start = time.time()
for _ in range(1000000):
    original_loop("content", [(1, 2, 3, 4, 5, 6, 7)])
print(f"Original: {time.time() - start:.4f}s")
