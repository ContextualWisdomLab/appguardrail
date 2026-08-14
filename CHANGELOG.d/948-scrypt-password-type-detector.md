# Issue #948 — Node scrypt password input-type detector

## Added

- Added the HIGH `javascript-auth-scrypt-unvalidated-password-type` detector family for source-derived `hashPassword` and `verifyPassword` functions that pass an unvalidated password parameter directly to Node.js `scryptSync`.
- Added exact vulnerable and reviewed fixed ScopeWeave Git-blob fixtures and production scanner regressions.
- Added negative coverage for string normalization, pre-sink type validation, and unrelated key-derivation helpers.

## Security

- Classifies the missing input-type boundary primarily as CWE-1287 and records the uncaught-exception consequence as CWE-248 rather than treating generic workflow cancellation or generic resource consumption as vulnerability proof.
- Keeps the multiline patterns function/character bounded and guarded by parser-safe prefilters.

## Documentation

- Added detector scope, remediation boundary, limitations, exact source provenance, and APA 7 references to CWE 4.20 and the current Node.js crypto contract.
