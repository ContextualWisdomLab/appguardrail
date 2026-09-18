import time
import os

def test_perf():
    candidates = ["src/file1.py", "src/file2.js", "src/file3.ts", "src/file4.go", "src/file5.rs"] * 10000

    start = time.time()
    count = 0
    for path in candidates:
        if path.endswith(".py"):
            count += 1
    print(f"endswith: {time.time() - start:.4f}s")

    start = time.time()
    count = 0
    for path in candidates:
        if path[-3:] == ".py":
            count += 1
    print(f"slice: {time.time() - start:.4f}s")

test_perf()
