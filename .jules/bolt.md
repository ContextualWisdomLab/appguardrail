## 2024-05-24 - File traversal performance
**Learning:** When optimizing os.walk combined with Path objects, replacing them with os.scandir and os.path.splitext reduces stat() calls drastically, but requires careful matching of symlink behavior (os.walk matches directory symlinks depending on arguments, Path.is_file() follows symlinks by default).
**Action:** Use entry.is_dir(follow_symlinks=False) to match os.walk and entry.is_file() to match Path.is_file() default.

## 2024-06-11 - Global state caching in Python tests
**Learning:** When aggressively caching global module state (like pre-extracted regex rules from `SCAN_RULES`), tests using `unittest.mock.patch` on that global state may fail because the cache retains stale references to the unpatched objects.
**Action:** Implement cache-busting logic (e.g., tracking `id(SCAN_RULES)`) to clear the cache when the object identity changes.

## 2024-06-13 - Optimizing multiple pathlib stat checks
**Learning:** Checking `Path.is_symlink()`, `Path.is_file()`, and `Path.stat().st_size` individually on a pathlib object invokes multiple separate `stat()` system calls and generates overhead. For hot paths scanning thousands of files, this adds up significantly.
**Action:** Replace multiple `Path` metadata checks with a single `os.lstat(path)` call and `stat` module bitwise checks (e.g., `stat.S_ISLNK(st.st_mode)`, `stat.S_ISREG(st.st_mode)`) to collapse everything into one highly performant system call.

## 2026-06-14 - Deferring Pathlib Operations in Hot Paths
**Learning:** In highly repetitive loops like file scanners (e.g., iterating through thousands of safe files), preemptively calculating `Path.relative_to()` and sanitizing strings adds significant cumulative overhead. Pathlib operations internally parse paths, check parts, and construct new objects, which is extremely expensive when executed on a per-file basis unconditionally.
**Action:** Always defer expensive path computations (like converting paths to relative or string sanitization) until *after* the fast-path condition (like a regex match) triggers. This drastically cuts down on unnecessary string operations for clean files.

## 2024-06-19 - Regex matching file scanning performance
**Learning:** For static analysis tools iterating over files and applying regexes, iterating line-by-line and applying regexes is slow due to the Python interpreter loop overhead. Reading the entire file into a string (provided it's not excessively large, which is protected by file size checks) and calling `rule.search()` to fast-fail, then using `rule.finditer()` to extract matches, is significantly faster because it pushes the heavy lifting down to C-level regex code.
**Action:** Always prefer `finditer` on the entire file content over line-by-line enumeration for regex matching in static analysis scanners.

## 2024-06-20 - Multi-line regex scanning pitfalls
**Learning:** When transitioning from line-by-line regex scanning to full-file scanning with `finditer`, removing line boundaries breaks any regex that depends on start (`^`) or end (`$`) line anchors. In addition, iterating over `finditer` is fast enough, and an explicit `search` check beforehand is an anti-pattern as it does redundant work if a match exists.
**Action:** Always add `re.MULTILINE` to regex patterns when switching to full-file scanning, and rely directly on `finditer` without a redundant `search` check.
