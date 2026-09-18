import time
from appguardrail_core.language import detect_language_axes

def test_perf():
    # Pass strings rather than Path objects (as it happens in _discover_files sometimes)
    candidates = ["src/file1.py", "src/file2.js", "src/file3.ts", "src/file4.go", "src/file5.rs", "test.xml", "test.yml"] * 100000

    start = time.time()
    for _ in range(10):
        detect_language_axes(candidates)
    print(f"Original String: {time.time() - start:.4f}s")

test_perf()
