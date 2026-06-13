## 2024-05-24 - File traversal performance
**Learning:** When optimizing os.walk combined with Path objects, replacing them with os.scandir and os.path.splitext reduces stat() calls drastically, but requires careful matching of symlink behavior (os.walk matches directory symlinks depending on arguments, Path.is_file() follows symlinks by default).
**Action:** Use entry.is_dir(follow_symlinks=False) to match os.walk and entry.is_file() to match Path.is_file() default.

## 2024-06-11 - Global state caching in Python tests
**Learning:** When aggressively caching global module state (like pre-extracted regex rules from `SCAN_RULES`), tests using `unittest.mock.patch` on that global state may fail because the cache retains stale references to the unpatched objects.
**Action:** Implement cache-busting logic (e.g., tracking `id(SCAN_RULES)`) to clear the cache when the object identity changes.
## 2026-06-13 - Optimize file scanning metadata checks
**Learning:** In tight file scanning loops, multiple `pathlib` method calls like `is_symlink()`, `is_file()`, and `stat()` trigger separate, expensive `stat()` system calls. This results in significant I/O overhead.
**Action:** Replace consecutive `pathlib` metadata checks with a single `os.lstat()` call combined with Python's `stat` module bitwise checks (e.g., `stat.S_ISLNK`, `stat.S_ISREG`). This reduces multiple system calls to just one, drastically improving performance.
