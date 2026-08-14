# Issue #775 — URL-token session revocation detector

## Added

- Added the HIGH `javascript-url-session-token-without-revocation` detector family for ScopeWeave calendar and stream routes that accepted query-string session JWTs through `verifyToken` without enforcing the application's current database-backed `token_version` revocation state.
- Added route-specific positive replays, the reviewed shared `verifySessionJwt` repair, an independently authored inline token-version negative, and middleware-only negative coverage.
- Added production `_scan_file` regression coverage requiring two normalized findings on the vulnerable replay and none on the reviewed fix.

## Security

- Records CWE-613 as an `ALLOWED-WITH-REVIEW` mapping for reusable stale session credentials rather than over-claiming a perfect taxonomy match.
- Keeps attachment-view authentication out of the positive corpus because the vulnerable source snapshot already enforced `token_version` there.

## Documentation

- Added exact vulnerable/fixed ScopeWeave Git-object identities, remediation and detector limitations, plus APA 7 references to CWE 4.20, the OWASP Session Management Cheat Sheet, and OWASP ASVS 5.0 V7.2.
