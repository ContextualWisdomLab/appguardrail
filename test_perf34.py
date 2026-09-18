import time
from pathlib import Path

def orig(path):
    return path.as_posix() if isinstance(path, Path) else path.replace("\\", "/")

def fast(path):
    return path.as_posix() if isinstance(path, Path) else (path if "\\" not in path else path.replace("\\", "/"))

def test_perf():
    path = "some/normal/unix/path.py"
    start = time.time()
    for _ in range(1000000):
        orig(path)
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(1000000):
        fast(path)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
