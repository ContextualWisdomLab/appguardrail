# Issues #462, #463, #468, and #469 — hardcoded JWT secret fallback detector

## Added

- Added the CRITICAL `javascript-jwt-hardcoded-secret-fallback` rule for a Node.js HS256 signing key that uses a hardcoded string when its environment variable is absent.
- Added exact vulnerable and reviewed fixed ScopeWeave source identities, nullish-coalescing coverage, runtime-random and non-signing negatives, and production scanner metadata assertions.
- Added a bounded three-token prefilter and a same-variable HMAC sink requirement to avoid classifying unrelated optional configuration as a JWT key weakness.

## Documentation

- Added the detector contract, remediation and token-rotation boundary, declared limitations, and APA 7 references to RFC 8725, CWE-321, CWE-798, and OWASP A07:2021.
- Consolidated four collected workflow events from ScopeWeave PR #387 into one detector family without dropping their source-change provenance.
