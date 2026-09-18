import time
import os

SKIP_EXTENSIONS = {
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".webm", ".pdf", ".zip", ".tar",
    ".gz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".class",
    ".jar", ".war", ".ear", ".map", ".log"
}

def orig(filename):
    idx = filename.rfind(".")
    ext = (
        filename[idx:]
        if idx > 0 and filename[:idx].replace(".", "")
        else ""
    )
    if ext.lower() not in SKIP_EXTENSIONS:
        return True
    return False

def fast(filename):
    idx = filename.rfind(".")
    if idx > 0 and filename[:idx].replace(".", ""):
        ext = filename[idx:].lower()
        if ext not in SKIP_EXTENSIONS:
            return True
        return False
    return True

def test_perf():
    filenames = ["test.py", "test.js", "test.svg", "test.png", "test", ".test", ".github", "package.json"] * 10000
    start = time.time()
    for _ in range(100):
        for f in filenames:
            orig(f)
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100):
        for f in filenames:
            fast(f)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
