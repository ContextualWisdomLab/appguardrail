## 2025-05-30 - Fix DoS vector in file scanner
**Vulnerability:** The CLI file scanner `vibesec scan` iterated through files using `os.walk` without verifying if a file was a regular file (`is_file()`) and read the entire file into memory using `Path.read_text()` without any size constraints.
**Learning:** If a malicious or overly broad directory was scanned (e.g., containing device nodes like `/dev/zero`, FIFOs, or gigabyte-sized files), the scanner would hang indefinitely or crash due to an Out of Memory (OOM) error.
**Prevention:** Always verify `Path.is_file()` before yielding files to scan to avoid reading character devices or FIFOs. In addition, explicitly check `Path.stat().st_size` against a reasonable upper bound (e.g., 10MB) before loading file content entirely into memory.

## 2025-05-31 - [CLI Scanner DoS and OOM Vulnerability Prevention]
**Vulnerability:** File-system-based Denial of Service (DoS) and Out-Of-Memory (OOM) risks during static analysis. The scanner could hang on special system files (like `/dev/zero` or FIFOs) or consume excessive memory.
**Learning:** The CLI tool lacked robust checks for file types before processing them. The reviewer pointed out that changing `for line in f` to `read_text().splitlines()` actually increased memory usage unnecessarily and degraded performance, and that `re.search` operates efficiently line-by-line without multiline vulnerabilities if iterating on the file object itself.
**Prevention:** Always verify `file_path.is_file()` to skip special files. Retain the memory-efficient line iterator (`for line in f`) while utilizing size limits (`st_size > 10MB`).

## 2025-06-08 - Fix Path Traversal and Arbitrary File Read via Symlinks
**Vulnerability:** The CLI file scanner `vibesec scan` used `os.walk` to traverse directories. While `os.walk` does not follow directory symlinks by default, `Path.is_file()` follows file symlinks. This could allow an attacker to read arbitrary files via symlinks (Arbitrary File Read) or traverse out of the intended directory context (Path Traversal).
**Learning:** Even if directory traversal does not follow symlinks by default (`os.walk`), individual file checks like `Path.is_file()` still follow symlinks and can result in reading arbitrary files.
**Prevention:** Replace `os.walk` with `os.scandir` to provide explicit control over symlink traversal. Check `entry.is_symlink()` and skip it, and use `follow_symlinks=False` in `is_dir()` and `is_file()` checks to ensure symlinks are completely ignored during file scanning.
