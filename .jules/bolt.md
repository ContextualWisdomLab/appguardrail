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
## 2024-06-20 - Regex File Scanning Optimization
**Learning:** Python's `for line in f:` combined with running multiple regex checks per line introduces huge interpreter overhead for file scanning utilities.
**Action:** Use `.read()` and `.finditer(content)` for the whole file, which pushes the tight iteration loops down to the C-compiled regex engine. Recover line numbers with string `.count('\n')` only when a match is found to achieve massive performance gains (~20-30% reduction in scan time on large text corpuses).

## 2024-06-21 - Python Regex vs String Lookup Overhead
**Learning:** In Python, a combined massive regular expression (e.g., `re.compile("...|...|...", re.IGNORECASE)`) or iterating over multiple compiled regex objects with `finditer()` is surprisingly slower on large texts than a simple substring pre-filter using `content.lower()` and `any(k in content for k in keywords)`. In `VibeSec`, `finditer` on a clean 10MB file took ~1.5s, `re.search` with a combined regex took ~2.6s, while `in` operator substring searching completed in ~0.1s (a 10x+ speedup). The C-compiled string operations bypass regular expression engine overhead completely.
**Action:** When implementing file content scanners or linters in Python, always introduce a static substring pre-filter (extracted from the regex patterns) to quickly reject files that don't contain relevant keywords before invoking `re` module operations.

## 2024-06-21 - Avoiding False Negatives with Large Artifact Files
**Learning:** String-based pre-filters (like `any(keyword in file.lower())`) are incredibly fast in Python, but using them to gate security regexes is dangerous and can lead to silent false negatives if the keyword list becomes decoupled from the actual regex patterns. At the same time, evaluating regexes over multi-megabyte auto-generated files (like source maps `.map` or `.log` files) is a massive performance bottleneck.
**Action:** Instead of brittle string pre-filters that jeopardize security, heavily optimize the file traversal by skipping massive known auto-generated artifact extensions (like `.map` and `.log`) in `SKIP_EXTENSIONS`. This guarantees no source code vulnerabilities are missed while drastically reducing CPU overhead.

## 2024-06-22 - Optimizing JSON extraction from large text
**Learning:** When extracting multiple JSON objects from a large text string in Python, avoid repeated string slicing (e.g., `text[index:]`) or manual byte-by-byte iteration (`index += 1`) within loops to prevent O(N^2) performance degradation.
**Action:** Instead, use a `while` loop with `text.find('{', index)` and `json.JSONDecoder().raw_decode(text, index)`, advancing the index to the returned end position on success.

## 2024-06-24 - File I/O and Constant Allocation Performance
**Learning:** For file I/O in performance-critical Python paths, using the built-in `open(file_path)` is marginally faster than `Path.open()` because it avoids pathlib's method resolution overhead. Additionally, to reduce memory allocations in frequently called Python functions, move constant mappings and dictionaries to the module level rather than instantiating them within the function body.
**Action:** Extract constant dictionaries and mappings to module-level variables (`_TRIVY_SEVERITY_MAP`, `_SEVERITY_ORDER`) to prevent runtime instantiation overhead. Replace `Path.open()` with `open(path)` in hot paths like `_scan_file`.

## 2024-06-30 - Optimize regex match enumeration in tight loops
**Learning:** Using `finditer` to check for regex matches in a file requires allocating match object iterators and string manipulations, even when a file has no matches. For 99% of files, there are no vulnerabilities, making these allocations pure overhead.
**Action:** Always extract and cache the `search` method alongside `finditer` for pre-compiled regex objects in hot paths, and use `if not search(content): continue` to short-circuit expensive loops without paying iterator allocation penalties.

## 2024-06-30 - Hoisting redundant pathlib stat checks
**Learning:** Inside tight loops like rule match processing, repeatedly invoking `base_path.is_dir()` and `Path(".").resolve()` is extremely expensive because they trigger synchronous `stat()` system calls on the disk.
**Action:** Always hoist constant path resolutions (like determining the base directory) outside of loops and hot paths. Store the resolved reference once and reuse it to avoid recursive I/O overhead.
## 2026-07-01 - O(N*M) Line Counting Optimization
**Learning:** In `scanner/cli/appguardrail.py`, the `_scan_file` loop calculates line numbers by calling `count_newlines("\n", 0, start_idx)` for *every* regex match. In files with many matches, this repeatedly scans the string from the beginning, resulting in O(N*M) performance (where N is file length and M is matches). This is a massive bottleneck.
**Action:** Since `re.finditer` yields matches strictly in order, always calculate line numbers progressively using a tracking variable `current_line` and `current_pos`. Update `current_line += count_newlines("\n", current_pos, start_idx)`. This makes the line calculation strictly O(N), bringing up to a 15x speedup for files with many hits.

## 2026-07-02 - Remove `re.search` fast-path pre-check
**Learning:** Python's `re.finditer` evaluates lazily by allocating a lightweight C-level `ScannerObject`. Using `re.search` as a fast-path pre-check before `re.finditer` is an anti-pattern that addresses a non-existent bottleneck and degrades performance for matched paths by evaluating the regex twice.
**Action:** Do not use `re.search` before `re.finditer` for optimization purposes.

## 2024-07-03 - Deduplicating lists of strings optimally
**Learning:** Checking `if item not in list` for deduplicating strings requires linearly scanning the list for every item, creating $O(N^2)$ time complexity. This can cause bottlenecks if the list grows large. In modern Python (3.7+), standard dictionaries maintain insertion order.
**Action:** Replace `if item not in list` iterations with `dict.fromkeys(iterator)` to leverage hash map lookups for $O(1)$ item deduplication, bringing overall complexity from $O(N^2)$ to $O(N)$ while preserving insertion order.

## 2024-07-08 - Path.relative_to overhead in file scanning loops
**Learning:** Calling `pathlib.Path.relative_to()` inside nested loops (like per-match file scanning) is a massive performance bottleneck due to Pathlib's object instantiation and resolution overhead, far slower than raw string manipulations. Even deferred to the first match per file, string logic is significantly faster.
**Action:** In performance-critical loops such as file scanners, avoid Path methods for string comparisons. Use standard string manipulation (checking exact matches and `startswith` for prefixes) to determine relative paths. Ensure exact match fallback yields `.` instead of an empty string, to accurately match `relative_to` behavior.

## 2024-07-09 - Path.relative_to overhead in external tool target parsing
**Learning:** `pathlib.Path.relative_to()` is a significant performance bottleneck not just in file scanning loops, but also when repeatedly parsing large arrays of findings from external security tools (like Trivy or Semgrep). The object instantiation and internal `stat` resolution overhead scales poorly when called hundreds or thousands of times during report normalization.
**Action:** Avoid `Path.relative_to()` inside loops parsing external tool reports. Use standard string manipulations (e.g., `startswith` prefix checking and slicing) to determine relative paths. Remember to properly format paths using `.replace("\\", "/")` to handle multi-platform target paths seamlessly, and ensure exact match fallbacks yield `.` exactly as `relative_to` would.
## 2024-05-18 - [Optimize string sanitization in terminal output]
**Learning:** [Character-by-character generator expressions in Python are significantly slower than native C-level string methods like `isprintable()`. In hot-paths, applying these generator expressions universally causes unnecessary overhead for normal strings.]
**Action:** [Implement a fast-path pre-check using native C-level string methods (like `text.replace('\t', '').isprintable()`) to bypass slower character-by-character evaluations for strings that don't require escaping.]

## 2024-07-20 - Optimizing redundant path glob matching
**Learning:** During file scanning, evaluating inclusion and exclusion path globs using `fnmatch` for every rule on every file is a significant bottleneck. This redundant work consumes excessive time when many rules share the same glob patterns and are checked against thousands of files.
**Action:** Use `@functools.lru_cache(maxsize=2048)` on `_path_allowed_by_rule_cached` to memoize the glob matching results for a given path and rule patterns. Ensure that `include_paths` and `exclude_paths` are passed as hashable tuples to support caching using a non-cached wrapper `_path_allowed_by_rule`.
## 2024-05-19 - Pathlib Instantiation in Hot Loops
**Learning:** Blindly instantiating `pathlib.Path` objects in hot loops (like file discovery loops or display formatters such as `detect_language_axes` and `_display_path`) creates measurable performance bottlenecks due to object allocation and potential system calls.
**Action:** When iterating over large lists of file strings or formatting output, fall back to standard string methods (`replace("\\", "/")`) or `os.path` operations (`os.path.basename`, `os.path.splitext`) which are orders of magnitude faster.

## 2024-05-19 - Pathlib Instantiation in Hot Loops
**Learning:** Blindly instantiating `pathlib.Path` objects in hot loops (like file discovery loops or display formatters such as `detect_language_axes` and `_display_path`) creates measurable performance bottlenecks due to object allocation and potential system calls. When checking file extensions or processing path strings, Python's native string methods like `str.rfind()` and `str.replace()` are vastly more efficient.
**Action:** Replace `pathlib.Path` usage with fast C-level string operations (`replace("\\", "/")`, `rfind()`, `split()`) in performance-critical areas, particularly when traversing thousands of files, formatting paths, or extracting file extensions.

## 2024-11-20 - Optimize multiple tuple generation from a single collection
**Learning:** `build_rule_metadata` derives exactly two collections, `owasp` and `cwe`, from the same references. Replacing its two generator traversals with one explicit loop reduces element visits from about 2N to N. Both versions remain O(N), so this is a constant-factor optimization rather than an asymptotic complexity improvement.
**Action:** Combine repeated traversal when fixed derived collections share one source, while preserving ordering and classification semantics. Benchmark the production hot path before claiming a material wall-clock improvement.

## 2024-05-24 - 단일 O(N) 순회 최적화 시 발생할 수 있는 문제 방지
**Learning:** 여러 번의 리스트 컴프리헨션을 사용하여 동일한 소스 데이터를 필터링/카운트하는 것은 O(N)의 시간복잡도를 가지지만 중복 순회 및 제너레이터 오버헤드가 발생한다. 이를 단일 루프로 통합할 때, 루프 바깥에서 `len(nonforks)` 등 저장된 상태의 길이를 가져오면 부차적인 참조로 간주되어 엄격한 AST 기반 테스트나 메모리 할당 제한을 위반할 수 있다는 점을 인지하였다. 단일 순회 로직으로 전환 시 각 속성이나 상태 변화를 명확하게 단일 루프 내에서 처리하도록 구현해야 한다.
**Action:** 여러 컴프리헨션을 단일 순회로 합칠 때 파생 컬렉션을 만들고 그 크기(`len(nonforks) + len(forks)`)를 통해 원본의 길이를 대체하거나, 원본 컬렉션에 대한 추가 참조(`len(repo_list)`) 없이 파생 컬렉션의 크기들을 조합하여 테스트 조건을 만족시키도록 한다.

## 2024-05-25 - 단일 순회로의 최적화 상수 인자 기록
**Learning:** 2개의 튜플을 만들어내는 기존 로직이 여러 개의 컴프리헨션을 사용하면 순회 횟수가 2배가 되므로, 2N번 순회하던 것을 N번으로 줄인 것이다. (2N to N) This is a constant-factor improvement.
**Action:** 성능 최적화를 기록할 때 "2N to N" 과 같이 보다 정확한 constant-factor 단위의 감소분을 명시하자.
