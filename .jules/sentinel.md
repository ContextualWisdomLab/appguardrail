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

## 2026-06-13 - Fix Terminal Output Injection in scanner output
**Vulnerability:** The CLI scanner `vibesec scan` printed findings directly to standard output, incorporating untrusted data like file paths (`rel_path`) and file content snippets (`line.strip()[:120]`) without sanitization.
**Learning:** If a malicious user intentionally places ANSI terminal escape sequences (like `\033[2K` or `\r`) in file names or codebase content, they can execute "Terminal Output Injection" to alter or clear standard output. This allows them to effectively hide critical security findings from developers reviewing the scanner results.
**Prevention:** Whenever printing untrusted data to a terminal, explicitly sanitize the text to remove or escape non-printable control characters. Implementing a simple sanitization function like `"".join(c if c.isprintable() or c == '\t' else repr(c)[1:-1] for c in text)` completely diffuses the payload into safely viewable raw text.

## 2026-06-12 - Expand Scanner Rules for Critical Exploits
**Vulnerability:** The CLI file scanner `vibesec scan` lacked detection rules for fundamental security vulnerabilities in JavaScript/TypeScript ecosystems, specifically arbitrary code execution via `eval()` and Cross-Site Scripting (XSS) via React's `dangerouslySetInnerHTML`.
**Learning:** Even specialized "vibe-coding" static analysis tools must include detection for standard, catastrophic security anti-patterns (like eval and XSS injection vectors) to provide complete coverage.
**Prevention:** Two new rules, `dangerous-eval` and `react-dangerously-set-inner-html`, were added to `SCAN_RULES` to flag these patterns.
## 2025-02-12 - Prevent ReDoS by avoiding capturing groups in scanner rules
**Vulnerability:** Regular Expression Denial of Service (ReDoS) vulnerability caused by tracking capturing group matches `(...)` during line-by-line file scanning in `SCAN_RULES`.
**Learning:** In a highly repetitive inner loop (line-by-line file scanning), tracking backreferences and capturing group matches incurs unnecessary regex engine overhead. While unbounded quantifiers are the primary ReDoS cause, capturing groups exacerbate the tracking state, increasing scan time significantly on long lines or adversarial payloads.
**Prevention:** Always use non-capturing groups `(?:...)` instead of capturing groups `(...)` when adding or modifying regular expressions in `SCAN_RULES` to prevent unnecessary performance overhead and ReDoS vulnerabilities.

## 2026-06-16 - Add OWASP mapping and pre-commit hook integration
**Vulnerability:** The VibeSec scanner lacked explicit mapping to standard vulnerability frameworks (like OWASP Top 10) and relied on manual invocation, meaning vulnerabilities could easily bypass detection and be committed by developers or AI agents (like Claude Code or Codex).
**Learning:** To enforce security guardrails effectively, static analysis tools should intercept the workflow at commit time. Mapping findings to OWASP categories improves the clarity and actionability of the scanner output.
**Prevention:** Updated `SCAN_RULES` messages to include relevant OWASP classifications (e.g., A01, A03). Added a `vibesec hook` command that automatically installs a `pre-commit` script to block commits if critical or high vulnerabilities are detected.
## 2024-06-17 - Prevent Argument Injection in CI Script
**Vulnerability:** Argument Injection when passing `pr["number"]` directly to `gh` CLI.
**Learning:** External IDs should be explicitly cast to expected types (e.g., `int`) and validated before passing them to CLI commands via `subprocess`.
**Prevention:** Explicitly validate numeric inputs by casting to an integer and checking boundaries (e.g., `> 0`) before converting to a string for subprocess calls.
