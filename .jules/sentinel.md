## 2025-05-30 - Fix DoS vector in file scanner
**Vulnerability:** The CLI file scanner `vibesec scan` iterated through files using `os.walk` without verifying if a file was a regular file (`is_file()`) and read the entire file into memory using `Path.read_text()` without any size constraints.
**Learning:** If a malicious or overly broad directory was scanned (e.g., containing device nodes like `/dev/zero`, FIFOs, or gigabyte-sized files), the scanner would hang indefinitely or crash due to an Out of Memory (OOM) error.
**Prevention:** Always verify `Path.is_file()` before yielding files to scan to avoid reading character devices or FIFOs. In addition, explicitly check `Path.stat().st_size` against a reasonable upper bound (e.g., 10MB) before loading file content entirely into memory.

## 2025-05-31 - [CLI Scanner DoS and OOM Vulnerability Prevention]
**Vulnerability:** File-system-based Denial of Service (DoS) and Out-Of-Memory (OOM) risks during static analysis. The scanner could hang on special system files (like `/dev/zero` or FIFOs) or consume excessive memory.
**Learning:** The CLI tool lacked robust checks for file types before processing them. The reviewer pointed out that changing `for line in f` to `read_text().splitlines()` actually increased memory usage unnecessarily and degraded performance, and that `re.search` operates efficiently line-by-line without multiline vulnerabilities if iterating on the file object itself.
**Prevention:** Always verify `file_path.is_file()` to skip special files. Retain the memory-efficient line iterator (`for line in f`) while utilizing size limits (`st_size > 10MB`).

## 2024-10-24 - [Path Traversal via Symlink Following in File Collector]
**Vulnerability:** Arbitrary File Read and Path Traversal. The static analyzer's file collection method (`_collect_files`) used `os.walk()` combined with `Path` creation without restricting symbolic link traversal.
**Learning:** `os.walk()` and standard `Path` traversals can inadvertently follow symbolic links. An attacker could craft a symlink pointing to sensitive system files (e.g., `/etc/passwd`) or files outside the target directory, causing the scanner to read and report contents from unauthorized locations.
**Prevention:** Avoid `os.walk()` when scanning untrusted directories. Use `os.scandir()` and explicitly check `entry.is_symlink()` to ignore symbolic links. Also pass `follow_symlinks=False` to `is_dir()` and `is_file()` checks to ensure symlink targets are not evaluated.
