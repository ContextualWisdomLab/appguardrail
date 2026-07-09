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

## 2025-06-25 - Expand Scanner Rules for Command Injection
**Vulnerability:** The VibeSec static analysis scanner lacked explicit detection for command injection patterns (such as `child_process.exec` with untrusted input in Node, or `subprocess.run(..., shell=True)` in Python).
**Learning:** Command Injection is a critical OWASP Top 10 vulnerability (A03:2021) that must be flagged in both JavaScript/TypeScript and Python codebases, especially in AI-assisted development where dynamic shell execution is often carelessly generated.
**Prevention:** Two new rules were added to `SCAN_RULES`: `node-command-injection` and `python-command-injection`. In addition, a `hardcoded-password` rule was added to capture generic password misconfigurations.

## 2026-06-25 - Expand Scanner Rules for Path Traversal
**Vulnerability:** The VibeSec static analysis scanner lacked explicit detection for path traversal risks caused by dynamically constructing file paths using untrusted inputs (e.g., Python `open(f"...{var}...")` or Node `fs.readFile(\`...\${var}...\`)`).
**Learning:** Path Traversal is a critical OWASP Top 10 vulnerability (A01:2021) that must be flagged. Constructing dynamic paths without validation or sanitization is a very common failure mode when AI generates file-system related code.
**Prevention:** A new rule `path-traversal-risk` was added to `SCAN_RULES` to flag unsafe usage of `fs.readFile`, `fs.readFileSync`, `fs.writeFile`, `fs.writeFileSync`, `fs.createReadStream`, and Python's `open()` when used with string concatenation, f-strings, or template literals.

## 2024-06-21 - [ReDoS Prevention in YAML Scanner Rules]
**Vulnerability:** Regular Expression Denial of Service (ReDoS) potential in scanner rules.
**Learning:** Capturing groups `(...)` in heavily used regex rules (like in `scanner/rules/*.yml`) increase backtracking overhead and memory usage, making the scanner vulnerable to ReDoS attacks with crafted input files.
**Prevention:** Always use non-capturing groups `(?:...)` when the captured value is not needed for backreferences or extraction. This improves scanner performance and prevents ReDoS.

## 2025-02-24 - Fix Insecure Deserialization in scanner output
**Vulnerability:** The CLI file scanner `vibesec scan` lacked detection rules for insecure deserialization, such as `pickle.load` or `yaml.load` in Python, which could lead to arbitrary code execution.
**Learning:** Adding regular expressions that detect known dangerous serialization libraries prevents severe security vulnerabilities when parsing untrusted data.
**Prevention:** A new scanner rule `python-insecure-deserialization` was added to `SCAN_RULES` to flag `pickle.load(s)`, `yaml.load`, and `marshal.load(s)`.
## 2025-02-28 - Prevent Security Theater in Validation Logic
**Vulnerability:** Redundant, useless security checks ("security theater") were previously added to statically hardcoded URL strings in GitHub actions and test files, under the guise of SSRF prevention.
**Learning:** Checking a hardcoded string like `"https://pypi.org/..."` to see if it starts with `https://` provides zero real security value while polluting the codebase and making PR reviews noisy. Security validation logic must be strictly scoped to where *untrusted, dynamic input* is introduced (like dynamically constructed API URLs in network wrappers).
**Prevention:** Avoid blanket application of security validation rules across an entire repository regardless of context. Always trace the source of the variable being validated to ensure it actually incorporates dynamic or external data before adding runtime verification logic.
## 2025-02-28 - Fix CodeQL Code Scanning Upload Error
**Vulnerability:** CI fails with error "CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled" when uploading SARIF results.
**Learning:** If a repository has default Code Scanning setup enabled in GitHub settings, pushing SARIF using the `github/codeql-action/upload-sarif` action from advanced workflows fails. This conflict happens when security tooling pushes SARIF files to the GitHub Advanced Security Code Scanning endpoint.
**Prevention:** Remove `github/codeql-action/upload-sarif` steps from advanced configuration workflows (like `scorecard-analysis.yml` and `security-process.yml`) if default CodeQL setup is enabled for the repository, to avoid pipeline failures and configuration conflicts.
## 2025-02-28 - Enhance SSRF Protection with IP Validation
**Vulnerability:** Weak redirect target validation for log collection flows in CI scripts. The `_validate_log_download_url` function blocked a static list of hosts (like `localhost` and `127.0.0.1`), but failed to block private/internal IP ranges (10.0.0.0/8, 192.168.0.0/16, etc), numeric encodings (like `2130706433`), or link-local IPv6 addresses.
**Learning:** Checking hostnames against a hardcoded blocklist is insufficient for SSRF protection because attackers can bypass the list using different IP representations or pointing to other internal IP ranges. Robust SSRF validation requires parsing the IP address using the `ipaddress` module and checking properties like `is_private`, `is_loopback`, `is_link_local`, etc.
**Prevention:** Use `ipaddress.ip_address` to parse and validate IP literals, explicitly rejecting private and reserved addresses before making network requests. Ensure edge cases like dotless decimal encoding and credentials in URLs are also rejected.
## 2025-02-28 - Note on IP parsing edge cases
**Learning:** Catching `ValueError` during `ipaddress.ip_address(raw)` and passing (which is necessary to allow valid hostnames like `example.com`), inadvertently allows IP formats that `ipaddress` rejects but `urllib` might accept (e.g., octal or hex encoded IP addresses like `http://0177.0.0.1/`). Full SSRF protection typically requires DNS resolution, but static check is still a massive improvement over basic string matching blocklists.
## 2025-02-28 - Note on CodeQL and external tools network flakiness
**Learning:** Network disruptions on runner environments (like `unable to access 'https://github.com/ContextualWisdomLab/appguardrail/': Could not resolve host: github.com` during OSV scanner execution) are transient infrastructure failures and not related to the codebase. When this occurs alongside CodeQL issues, re-running the job is the appropriate action.
