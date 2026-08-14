# Newsdom Authorization HMAC Unicode-string detector family

## Added

- Added the HIGH `python-auth-header-compare-digest-unicode-string` rule for the source-derived FastAPI authentication shape that passes an unvalidated Unicode Authorization string directly to Python `hmac.compare_digest`.
- Added vulnerable-source, protected-fixed-source, explicit UTF-8 conversion, ASCII-rejection, and non-authentication negative regressions plus production `_scan_file` finding assertions.
- Consolidated the equivalent core weakness collected from Newsdom API PRs #487, #489, #493, #495, and #499 while preserving their AppGuardrail issue provenance.

## Security

- Records CWE-248 as the concrete uncaught-exception consequence and CWE-20 as the surrounding missing input-validation boundary.
- Keeps the separate oversized-header resource bound introduced by Newsdom PR #497 out of scope instead of over-claiming detector coverage.

## Documentation

- Added exact vulnerable/fixed repository revision and blob identities, bounded detection/remediation contracts, limitations, and APA 7 references to Python 3.14.6 and CWE 4.20.
