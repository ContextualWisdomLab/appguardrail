# Keyverse PR #32 source-backed detector family

## Added

- Added the HIGH `python-scim-put-tombstone-resurrection` detector for a SCIM User PUT that performs full replacement without first preserving the application's merged-account tombstone invariant.
- Added the MEDIUM `python-healthcheck-unrestricted-url-scheme` detector for a configurable container health URL passed directly to Python's default `urllib.request.urlopen` without an HTTP(S) scheme boundary.
- Added reviewed protected-main negatives, independent equivalent-safe negatives, and production `_scan_file` regressions for both source families.
- Consolidated the SAST-capable source changes behind Keyverse PR #32 while retaining the individual Strix collector issue identities.

## Security

- Maps the SCIM workflow defect to CWE-841 and the dynamic URL protocol boundary to CWE-918.
- Preserves the healthcheck source's defense-in-depth status: the collected Keyverse source describes the URL as a container self-probe rather than attacker-controlled input, so the detector does not overstate remote SSRF exploitability.
- Leaves generic Required OpenCode Review cancellation issues outside this detector closure family.

## Documentation

- Added exact vulnerable/protected-fixed Git object identities, bounded detector contracts, remediation and limitations, and APA 7 references to RFC 7644, CWE 4.20, and Python 3.14.6.
