## 2025-05-30 - Fix DoS vector in file scanner
**Vulnerability:** The CLI file scanner `vibesec scan` iterated through files using `os.walk` without verifying if a file was a regular file (`is_file()`) and read the entire file into memory using `Path.read_text()` without any size constraints.
**Learning:** If a malicious or overly broad directory was scanned (e.g., containing device nodes like `/dev/zero`, FIFOs, or gigabyte-sized files), the scanner would hang indefinitely or crash due to an Out of Memory (OOM) error.
**Prevention:** Always verify `Path.is_file()` before yielding files to scan to avoid reading character devices or FIFOs. In addition, explicitly check `Path.stat().st_size` against a reasonable upper bound (e.g., 10MB) before loading file content entirely into memory.

## 2025-05-31 - [CLI Scanner DoS and OOM Vulnerability Prevention]
**Vulnerability:** File-system-based Denial of Service (DoS) and Out-Of-Memory (OOM) risks during static analysis. The scanner could hang on special system files (like `/dev/zero` or FIFOs) or consume excessive memory.
**Learning:** The CLI tool lacked robust checks for file types before processing them. The reviewer pointed out that changing `for line in f` to `read_text().splitlines()` actually increased memory usage unnecessarily and degraded performance, and that `re.search` operates efficiently line-by-line without multiline vulnerabilities if iterating on the file object itself.
**Prevention:** Always verify `file_path.is_file()` to skip special files. Retain the memory-efficient line iterator (`for line in f`) while utilizing size limits (`st_size > 10MB`).

## 2024-06-07 - Symlink Path Traversal via os.walk
**Vulnerability:** The CLI file scanner `_collect_files` used `os.walk` and `Path.is_file()` without explicitly checking for or ignoring symbolic links, potentially causing Arbitrary File Read and Path Traversal if executed in repositories with malicious symlinks.
**Learning:** `os.walk` combined with `Path.is_file()` follows symlinks by default unless strict checks are employed. Python's `os.scandir` caches file attributes, improving performance while allowing explicit `is_symlink()` skipping and `follow_symlinks=False` enforcement.
**Prevention:** In static analysis and file parsing tools, explicitly avoid traversing symbolic links by using `os.scandir()` with `if entry.is_symlink(): continue` and passing `follow_symlinks=False` to `is_dir()` and `is_file()`.
