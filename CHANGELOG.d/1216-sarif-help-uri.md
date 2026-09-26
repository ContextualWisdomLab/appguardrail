### Fixed

- SARIF rule metadata now emits only absolute web URLs in `helpUri`, maps the
  repository's OWASP Top 10:2021 labels to canonical OWASP pages, and preserves
  human-readable reference labels in `help.text`. Malformed hosts, whitespace,
  control characters, and incomplete percent escapes are skipped without
  aborting SARIF generation (#1216).
