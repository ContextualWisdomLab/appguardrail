## 2026-06-30 - [Optimize File Filtering Globs]
**Learning:** `fnmatch.fnmatch` parsing within a deep nested loop for path matching incurs significant overhead during file tree traversal scanning.
**Action:** Pre-compile glob patterns into native regular expressions using `fnmatch.translate` during rule loading, rather than evaluating globs for every file. This avoids repetitive path normalization and regex translation during execution time. Ensure recursive globs like `**/` translate correctly to `(?:.*/)?`.
