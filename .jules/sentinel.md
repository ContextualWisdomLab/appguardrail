## 2025-05-30 - Fix DoS vector in file scanner
**Vulnerability:** The CLI file scanner `vibesec scan` iterated through files using `os.walk` without verifying if a file was a regular file (`is_file()`) and read the entire file into memory using `Path.read_text()` without any size constraints.
**Learning:** If a malicious or overly broad directory was scanned (e.g., containing device nodes like `/dev/zero`, FIFOs, or gigabyte-sized files), the scanner would hang indefinitely or crash due to an Out of Memory (OOM) error.
**Prevention:** Always verify `Path.is_file()` before yielding files to scan to avoid reading character devices or FIFOs. In addition, explicitly check `Path.stat().st_size` against a reasonable upper bound (e.g., 10MB) before loading file content entirely into memory.

## 2025-05-31 - [CLI Scanner DoS and OOM Vulnerability Prevention]
**Vulnerability:** File-system-based Denial of Service (DoS) and Out-Of-Memory (OOM) risks during static analysis. The scanner could hang on special system files (like `/dev/zero` or FIFOs) or consume excessive memory.
**Learning:** The CLI tool lacked robust checks for file types before processing them. The reviewer pointed out that changing `for line in f` to `read_text().splitlines()` actually increased memory usage unnecessarily and degraded performance, and that `re.search` operates efficiently line-by-line without multiline vulnerabilities if iterating on the file object itself.
**Prevention:** Always verify `file_path.is_file()` to skip special files. Retain the memory-efficient line iterator (`for line in f`) while utilizing size limits (`st_size > 10MB`).

## 2026-06-09 - Fix Path Traversal/Arbitrary File Read in scanner via symlinks
**Vulnerability:** The `_collect_files` function in `scanner/cli/vibesec.py` used `os.scandir` without explicitly checking if entries were symbolic links before processing them as directories or files. This could allow for arbitrary file read or path traversal vulnerabilities by processing symlinks that point outside the expected directories.
**Learning:** During static analysis, directory and file collection methods must be robust against maliciously crafted directory structures, specifically symbolic links pointing to sensitive system files.
**Prevention:** Explicitly use `entry.is_symlink()` and check `follow_symlinks=False` on `is_file()` to prevent traversing external links or including them during scan operations.

## 2026-06-11 - Fix Arbitrary File Write via symlink path traversal in `vibesec init`
**Vulnerability:** The `cmd_init` command in `scanner/cli/vibesec.py` created files and directories inside `.cursor/rules` or `VIBESEC_CHECKLIST.md` in the current project root. However, if the project directory contained malicious symlinks (e.g., `.cursor -> /etc` or `.cursor -> /tmp`), the CLI would unknowingly traverse the symlink and write files (e.g., `vibesec.md`) outside the intended directory. This leads to an Arbitrary File Write vulnerability, potentially allowing attackers to overwrite sensitive files or escalate privileges on the victim's machine.
**Learning:** Even simple CLI file operations (like initializing project configurations) are susceptible to Path Traversal via symlinks. When dealing with directory structures that could be maliciously crafted, we cannot trust that `Path(".").resolve() / ".cursor"` stays within the bounds of `Path(".").resolve()`.
**Prevention:** Before performing any filesystem mutation operations (e.g. `mkdir` or `write_text`), ensure the fully resolved path resides strictly within the expected parent boundary. Use `target_file.resolve().is_relative_to(project_root)` as a security check to detect and abort if the path escapes the intended directory.
