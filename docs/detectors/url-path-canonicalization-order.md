# URL-path canonicalization-order detector

**Status:** Accepted source-derived detector slice  
**Rule ID:** `python-url-path-traversal-validate-before-canonicalize`  
**Primary weakness classes:** CWE-180, CWE-22  
**Source event:** AppGuardrail issue #489, derived from `ContextualWisdomLab/naruon` PR #1206 at source head `0547162be7fdc958e375e69b05e0e3b1c26e1074`

## Buyer-visible protection

A URL-path validator can reject literal `.` and `..` segments while still accepting percent-encoded or multiply encoded equivalents. If a downstream URL consumer decodes a different representation, validation has protected the wrong value. The packaged rule detects the bounded Python source shape observed in the source event and emits a deploy-blocking HIGH finding before that pattern reaches production.

## Detection contract

The lightweight detector reports a finding only when one function contains all of the following evidence:

1. a path-like local variable is assigned from a stripped external value;
2. the same variable is treated as a URL path by checking a leading slash and excluding scheme, query, and fragment markers;
3. literal `.` and `..` segments are checked on that still-encoded variable;
4. the same variable is returned unchanged;
5. no `unquote(...)` or `unquote_to_bytes(...)` call canonicalizes that variable before the checks.

The regex is function-bounded and size-bounded. A four-token prefilter (`.split(`, `.startswith(`, `://`, and `return`) avoids evaluating the multiline expression for unrelated Python files.

## Source-authoritative evidence corpus

`tests/test_path_canonicalization_rules.py` preserves two independent oracles:

- **Positive replay:** the pre-fix CardDAV TXT context-path shape, where literal dot-segment checks were applied to `path` and the original value was returned.
- **Negative replay:** the fixed shape, where a bounded decoded representation is validated and that same representation is returned.

Additional negatives cover same-variable decoding before validation and generic local-path segment checks that do not carry the URL-path guard signature. The tests execute both the compiled packaged rule and the production `_scan_file` entrypoint, including normalized severity, category, CWE, OWASP, source line, and confidence metadata.

## Remediation boundary

The finding does not prescribe blind repeated decoding. The repair must follow the interpretation contract of the actual consumer:

1. parse the URI into components before decoding component data;
2. produce one explicit canonical representation for the path;
3. reject ambiguous or residual encoding that would be interpreted again downstream;
4. validate dot segments, separators, controls, and application-specific allowlists on that representation;
5. pass the same validated representation to the URL consumer.

RFC 3986 distinguishes component parsing, percent-encoding normalization, and dot-segment removal, and warns against repeatedly decoding the same string. CWE-180 likewise requires canonicalization before validation and identifies double decoding as a related failure mode. The source replay keeps the detector tied to observed code while this document keeps remediation tied to authoritative standards.

## Declared limitations

This is not a general interprocedural taint engine. It intentionally does not claim coverage for:

- validation and consumption split across functions;
- alternate decoder APIs not named `unquote` or `unquote_to_bytes`;
- languages other than Python;
- filesystem-only paths without the URL guard signature;
- custom frameworks that canonicalize implicitly before this source shape.

Those cases require separate source-derived detector obligations or a structural/dataflow engine. Expanding this regex without an independent positive and fixed-negative corpus is prohibited because wider matching would create unsupported efficacy claims.

## APA 7 references

Berners-Lee, T., Fielding, R., & Masinter, L. (2005). *Uniform resource identifier (URI): Generic syntax* (RFC 3986). RFC Editor. https://doi.org/10.17487/RFC3986

MITRE Corporation. (2026). *CWE-22: Improper limitation of a pathname to a restricted directory ('path traversal')* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/22.html

MITRE Corporation. (2026). *CWE-180: Incorrect behavior order: Validate before canonicalize* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/180.html

OWASP Foundation. (2021). *A01:2021—Broken access control*. https://owasp.org/Top10/A01_2021-Broken_Access_Control/
