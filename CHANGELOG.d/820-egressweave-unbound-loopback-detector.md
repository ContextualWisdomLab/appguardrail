# EgressWeave hostname-unbound loopback SSRF detector family

## Added

- Added the HIGH `python-ssrf-allow-local-unbound-loopback` detector for a global-address validator that enables `allow_local` and accepts loopback solely from the resolved IP, without binding the exception to the original hostname.
- Added vulnerable, reviewed-fixed, hostname-bound and non-SSRF regressions plus production `_scan_file` evidence.
- Consolidated repeated Strix collector events from EgressWeave PR #1 while preserving each issue identity.

## Security

- Classifies the source-derived weakness as CWE-918 / OWASP A10:2021 SSRF.
- Keeps broader private-address classification, resolver, redirect, proxy and connection-pool semantics outside the rule's declared source shape.

## Documentation

- Added exact vulnerable/fixed Git object identities, remediation and false-positive/false-negative boundaries, and APA 7 references to CWE 4.20, Python 3.14.6 `ipaddress`, RFC 1918 and RFC 4193.
