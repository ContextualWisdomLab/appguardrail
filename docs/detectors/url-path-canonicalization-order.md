# URL-path canonicalization-order detector

**Status:** Accepted source-derived detector slice  
**Rule ID:** `python-url-path-traversal-validate-before-canonicalize`  
**Primary weakness classes:** CWE-180, CWE-22  
**Collected issue family:** AppGuardrail issues #489, #502, and #503  
**Source change:** `ContextualWisdomLab/naruon` PR #1206; collected heads `cf5a1b0bd21cac2e2fa7ff61d5eca0cdad3db1c1` and `fedf06b7eec7e6cd4e1a8b27b864d5152ff98b84`; vulnerable source blob `d12c23a46afc6f2f6a38321e326e64cf7f3a1436`; analyzed fixed head `0547162be7fdc958e375e69b05e0e3b1c26e1074`; fixed source blob `c1a475a18566d6cb62946a43b533a53ddd5bd4e2`

## Buyer-visible protection

A URL-path validator can reject literal `.` and `..` segments while still accepting percent-encoded or multiply encoded equivalents. A second variant can decode and validate a safe representation but accidentally return the original encoded representation to the downstream consumer. In both cases validation protects a different value from the value that is executed. The packaged rule detects these bounded Python source shapes and emits a deploy-blocking HIGH finding before that mismatch reaches production.

## Detection contract

The lightweight detector contains two source-derived subpatterns under one weakness identity.

### Raw-value validation before canonicalization

A finding requires one function to contain all of the following evidence:

1. a path-like local variable assigned from a stripped external value;
2. URL-path guards on that same still-encoded variable: a leading slash plus an explicit scheme-delimiter exclusion (`"://" not in <same variable>`);
3. literal `.` and `..` segment checks on that variable;
4. the same variable returned unchanged;
5. no `unquote(...)` or `unquote_to_bytes(...)` call canonicalizing that variable before validation.

### Canonical-value validation followed by raw-value return

A finding requires one function to contain all of the following evidence:

1. a stripped raw path variable;
2. a distinct canonical variable initialized from the raw value;
3. `unquote(...)` or `unquote_to_bytes(...)` applied to the canonical variable;
4. URL-path leading-slash and same-variable scheme-delimiter exclusion plus literal dot-segment guards applied to that canonical variable;
5. the original raw variable returned instead of the validated canonical variable.

Both expressions are function-bounded and size-bounded. A four-token prefilter (`.split(`, `.startswith(`, `://`, and `return`) avoids evaluating the multiline expressions for unrelated Python files. The historical source also rejects query and fragment delimiters; those checks remain part of the replay corpus but are not structural prerequisites of the compact production regex, so the detector does not claim that narrower guard signature.

## Source-authoritative evidence corpus

Two focused test modules preserve distinct obligations:

- `tests/test_path_canonicalization_historical_replay.py` replays the exact collected Naruon source shape from vulnerable blob `d12c23a46afc6f2f6a38321e326e64cf7f3a1436`: `decoded_path` is canonicalized and validated, but raw `path` is returned. The reviewed fixed negative returns `decoded_path` and is pinned to head `0547162be7fdc958e375e69b05e0e3b1c26e1074` and blob `c1a475a18566d6cb62946a43b533a53ddd5bd4e2`.
- `tests/test_path_canonicalization_rules.py` covers the earlier raw validate-before-decode shape, a same-variable decode fix, generic non-URL local-path negatives, parser/prefilter contracts, and black-box production `_scan_file` metadata.

The oracle is not a Boolean embedded in source input. Tests assert expected detection independently, execute the compiled packaged rules and production scanner entrypoint, and verify normalized severity, category, CWE, OWASP, source line, and confidence metadata.

## Remediation boundary

The finding does not prescribe blind repeated decoding. The repair must follow the interpretation contract of the actual consumer:

1. parse the URI into components before decoding component data;
2. produce one explicit canonical representation for the path;
3. reject ambiguous or residual encoding that would be interpreted again downstream;
4. validate dot segments, separators, controls, and application-specific allowlists on that representation;
5. pass the same validated representation to the URL consumer.

RFC 3986 distinguishes component parsing, percent-encoding normalization, and dot-segment removal, and warns against repeatedly decoding the same string. CWE-180 likewise requires canonicalization before validation and identifies double decoding as a related failure mode. The exact source replay keeps the detector tied to observed code while this document keeps remediation tied to authoritative standards.

## Declared limitations

This is not a general interprocedural taint engine. It intentionally does not claim coverage for:

- validation and consumption split across functions;
- alternate decoder APIs not named `unquote` or `unquote_to_bytes`;
- languages other than Python;
- filesystem-only paths without the URL guard signature;
- custom frameworks that canonicalize implicitly before these source shapes;
- representation mismatches that do not preserve the bounded raw/canonical assignment relationship.

Those cases require separate source-derived detector obligations or a structural/dataflow engine. Expanding these regexes without an independent positive and fixed-negative corpus is prohibited because wider matching would create unsupported efficacy claims.

## APA 7 references

Berners-Lee, T., Fielding, R., & Masinter, L. (2005). *Uniform resource identifier (URI): Generic syntax* (RFC 3986). RFC Editor. https://doi.org/10.17487/RFC3986

MITRE Corporation. (2026). *CWE-22: Improper limitation of a pathname to a restricted directory ('path traversal')* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/22.html

MITRE Corporation. (2026). *CWE-180: Incorrect behavior order: Validate before canonicalize* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/180.html

OWASP Foundation. (2021). *A01:2021—Broken access control*. https://owasp.org/Top10/A01_2021-Broken_Access_Control/
