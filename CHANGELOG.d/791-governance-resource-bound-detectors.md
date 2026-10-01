# Issue #791 — governance resource-bound detector family

## Added

- Added the MEDIUM `python-governance-unbounded-json-load` rule for the source-derived fast-mlsirm governance reader that passed a path-backed stream directly to `json.load` without the repository's descriptor-safe bounded reader.
- Added the MEDIUM `python-governance-subprocess-without-timeout` rule for source-derived `_run_gh*` governance subprocesses that omit an explicit timeout.
- Added source-derived positive and negative regressions plus production `_scan_file` evidence.

## Security

- Keeps a `path.stat()` then reopen size check in scope because it does not bind validation to the descriptor that is actually parsed.
- Limits the subprocess rule to GitHub-governance helper shapes instead of classifying every `subprocess.run` call as a vulnerability.
- Maps the concrete availability/resource-bound defects to CWE-400 without treating the failed Strix workflow itself as security proof.

## Documentation

- Added exact vulnerable, partial-repair, and protected source identities plus APA 7 references to CWE 4.20 and Python 3.14.6 JSON/subprocess guidance.
