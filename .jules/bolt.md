## 2024-05-24 - File traversal performance
**Learning:** When optimizing os.walk combined with Path objects, replacing them with os.scandir and os.path.splitext reduces stat() calls drastically, but requires careful matching of symlink behavior (os.walk matches directory symlinks depending on arguments, Path.is_file() follows symlinks by default).
**Action:** Use entry.is_dir(follow_symlinks=False) to match os.walk and entry.is_file() to match Path.is_file() default.

## 2024-06-11 - Global state caching in Python tests
**Learning:** When aggressively caching global module state (like pre-extracted regex rules from `SCAN_RULES`), tests using `unittest.mock.patch` on that global state may fail because the cache retains stale references to the unpatched objects.
**Action:** Implement cache-busting logic (e.g., tracking `id(SCAN_RULES)`) to clear the cache when the object identity changes.
