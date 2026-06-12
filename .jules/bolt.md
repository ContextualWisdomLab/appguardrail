## 2024-05-24 - File traversal performance
**Learning:** When optimizing os.walk combined with Path objects, replacing them with os.scandir and os.path.splitext reduces stat() calls drastically, but requires careful matching of symlink behavior (os.walk matches directory symlinks depending on arguments, Path.is_file() follows symlinks by default).
**Action:** Use entry.is_dir(follow_symlinks=False) to match os.walk and entry.is_file() to match Path.is_file() default.

## 2026-06-12 - Scanner rule search caching
**Learning:** Building applicable rule lists and looking up each compiled regex `.search` method for every scanned file adds overhead in the hot scanning loop.
**Action:** Cache per-extension `(search, rule)` pairs and clear the cache whenever tests or callers replace the `SCAN_RULES` object.
