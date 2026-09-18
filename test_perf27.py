import time
import os

SKIP_EXTENSIONS = {
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".webm", ".pdf", ".zip", ".tar",
    ".gz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".class",
    ".jar", ".war", ".ear", ".map", ".log"
}

def skip_logic_orig(entry_name):
    idx = entry_name.rfind(".")
    ext = (
        entry_name[idx:]
        if idx > 0 and entry_name[:idx].replace(".", "")
        else ""
    )
    if ext.lower() not in SKIP_EXTENSIONS:
        return True
    return False

def skip_logic_fast(entry_name):
    idx = entry_name.rfind(".")
    if idx > 0 and entry_name[:idx].replace(".", ""):
        if entry_name[idx:].lower() not in SKIP_EXTENSIONS:
            return True
        return False
    return True

def test_perf():
    # simulate thousands of files
    names = ["app.js", "style.css", "icon.svg", "image.png", ".gitignore", "Dockerfile", "package.json", "data.json", "index.html"] * 10000
    start = time.time()
    for _ in range(100):
        for name in names:
            skip_logic_orig(name)
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100):
        for name in names:
            skip_logic_fast(name)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
