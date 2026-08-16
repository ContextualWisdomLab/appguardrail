# Issue #948 — Node scrypt password input-type detector

## Added

- Added the HIGH `javascript-auth-scrypt-unvalidated-password-type` detector family for source-derived `hashPassword` and `verifyPassword` functions that pass an unvalidated password parameter directly to Node.js `scryptSync`.
- Added exact vulnerable and reviewed fixed ScopeWeave Git-blob fixtures, commit/path-to-blob provenance verification, and production scanner regressions.
- Added negative coverage for string normalization, fail-closed pre-sink type validation, and unrelated key-derivation helpers, plus positive coverage for TypeScript parameters, nested blocks, and non-terminating type comparisons.

## Security

- Classifies the missing input-type boundary as CWE-1287. The detector does not claim CWE-248 because it does not prove whether a `scryptSync` exception is caught or uncaught, and it does not treat generic workflow cancellation or generic resource consumption as vulnerability proof.
- Keeps the multiline patterns function/character bounded and guarded by parser-safe prefilters, while suppressing only the explicitly supported immediate `return`/`throw` string-type rejection shape.

## Documentation

- Added detector scope, remediation boundary, limitations, exact source provenance, and APA 7 references to CWE 4.20 and the current Node.js crypto contract.
