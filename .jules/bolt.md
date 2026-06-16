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

## 2024-06-16 - Hot Loop Tuple Unpacking
**Learning:** In the Python CLI scanner, caching rules as dictionaries and accessing them via keys (e.g., `rule["search"](line)`) in hot loops (like scanning every line of a file) adds unnecessary overhead. By caching the rules as tuples and unpacking them (e.g., `rule_id, severity, message, search_func = rule`), we can bypass dictionary lookup and attribute access overhead entirely.
**Action:** Optimize tight loops by storing configuration or objects as tuples and unpacking them directly within the loop.

## 2024-06-16 - O(1) Memory Usage for File Scanning
**Learning:** When optimizing file scanning in Python, avoid using `f.read()` to load the entire file into memory unless specifically designed to handle large files efficiently. While it might feel faster due to native C execution with `re.finditer`, it loses `O(1)` memory efficiency and can cause out-of-memory regressions on large files, even if soft file size limits are enforced.
**Action:** Stick to line-by-line iteration (`for line in f:`) combined with `re.search` to process files safely without ballooning memory usage.
