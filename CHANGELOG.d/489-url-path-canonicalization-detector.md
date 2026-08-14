# Issue #489 — URL-path canonicalization-order detector

## Added

- Added the packaged HIGH-severity `python-url-path-traversal-validate-before-canonicalize` rule for the bounded Python URL-path shape derived from the Naruon CardDAV incident.
- Added source-authoritative positive and fixed-negative replays through the production scanner, including normalized line, category, confidence, CWE-180, CWE-22, and OWASP metadata assertions.
- Added a four-token prefilter and explicit false-positive boundaries for canonicalized and non-URL path validation.

## Documentation

- Added an authoritative detector contract, limitations, remediation boundary, and APA 7 references for RFC 3986, CWE-180, CWE-22, and OWASP A01:2021.
- Updated cross-cutting traceability so issue #489 can close only through executable detector evidence and protected-head merge gates.
