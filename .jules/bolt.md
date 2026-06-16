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

## 2024-05-18 - Set literal vs Tuple membership check

**Learning:** In Python, using set literals for constant membership checks (e.g., `in {'CRITICAL', 'HIGH'}`) inside loops or comprehensions is highly efficient because CPython optimizes them into `frozenset` constants at compile time, eliminating runtime instantiation overhead. Using `tuple` for these checks performs an `O(n)` linear search, while a `frozenset` performs an `O(1)` hash lookup.

**Action:** Prefer set literals `in {"A", "B"}` over tuples `in ("A", "B")` when performing membership checks against constant items, especially in hot paths or tight loops.

## 2024-05-30 - Optimize regex scanning using re.finditer
**Learning:** For file scanning, reading the file entirely (if within size limits) and using `re.finditer` over the full content uses native C implementations for searching, and calculates matches dramatically faster (over 2x) than reading and looping line-by-line via Python's interpreter.
**Action:** Always favor `re.finditer` or full-string string matching where large text files are involved, provided strict memory and file size limits are verified and enforced.

## 2024-06-16 - Parallelize Subprocess CLI Calls
**Learning:** Sequential, synchronous execution of `subprocess.run` (like calling the GitHub CLI) across multiple items (like PRs) is a significant I/O bottleneck.
**Action:** Use `concurrent.futures.ThreadPoolExecutor` with `functools.partial` and `executor.map` to safely parallelize I/O-bound subprocess executions, significantly reducing overall script runtime.
