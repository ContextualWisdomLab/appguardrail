# Python HMAC Authorization-header encoding detector

**Status:** Source-derived detector slice  
**Rule ID:** `python-auth-header-compare-digest-unicode-string`  
**Primary consequence:** CWE-248  
**Input-validation context:** CWE-20  
**Collected source family:** Newsdom API PRs #487, #489, #493, #495, and #499; AppGuardrail collector issues #715, #723, #733, #740, #741, #796, #802, #804, and #811

## Buyer-visible protection

Python's `hmac.compare_digest` is appropriate for constant-time comparisons, but its string form is restricted to ASCII-only strings. An HTTP Authorization header is attacker-controlled text. If a FastAPI dependency preserves the header as a Python `str` and passes a Unicode value directly to `compare_digest`, a non-ASCII credential can reach an exception path instead of the intended authentication denial.

The source-derived detector reports the bounded Newsdom source shape where `require_authorization` receives an `authorization` value through FastAPI `Header()`, assigns `provided = authorization or ""`, and later calls `hmac.compare_digest(provided, ...)` before rejecting non-ASCII input or converting the comparison operand to bytes.

## Source-authoritative evidence

Collector workflow outcomes are provenance only. Detector efficacy is derived from source objects and reviewed source behavior:

- repository: `ContextualWisdomLab/newsdom-api`;
- vulnerable base head: `04491c0e9ac38b9f793029683cebfb8210ccfadd`;
- vulnerable `src/newsdom_api/main.py` blob: `4efdad56ed78ed5c0158cdf0d746aedfe72604fe`;
- protected fixed head: `e06b1f3fb10903569124af011da213951e6e2473`;
- fixed `src/newsdom_api/main.py` blob: `f61aafc2d6592f4a84c7b02b50cfe4a972623463`.

Several generated security PRs independently targeted the same base-source weakness. They are consolidated into one detector family because their core source change was the same: remove direct Unicode-string comparison at the authentication boundary. PR #497 also added an independent header-length bound; that resource-bound obligation is deliberately not claimed by this detector.

The current protected Newsdom implementation is a stronger negative oracle than the generated branches: it acquires the Authorization value as bytes, bounds its length, parses a byte-oriented Bearer scheme, and compares credential bytes to a UTF-8 encoded configured token.

## Detection contract

The lightweight rule requires all of these source-shape signals in one Python file:

1. a `require_authorization` function;
2. FastAPI `Header()` evidence;
3. `provided = authorization or ""`;
4. a later `hmac.compare_digest(provided, ...)` call within a bounded function window;
5. no preceding `provided.isascii()` / `authorization.isascii()` rejection;
6. no preceding `provided.encode(...)` conversion.

The file-level prefilter uses `hmac.compare_digest(`, `Header()`, and `provided = authorization or`. Each token is parser-safe for AppGuardrail's lightweight inline-list loader.

## Remediation boundary

A safe implementation can use either of two explicit boundaries:

- reject non-ASCII string credentials before a string-to-string `compare_digest`; or
- encode both compared values to bytes before the constant-time comparison.

For HTTP authentication, a byte-oriented header parser is preferable when the framework permits it because the request-size bound, scheme parsing, and comparison representation can be made explicit before the cryptographic sink.

## Declared limitations

This rule is intentionally not a generic Python HMAC dataflow engine. It does not claim coverage for:

- authentication helpers with other function or variable names;
- caller-side validation or normalization;
- values sourced from frameworks other than the tested FastAPI `Header()` shape;
- `secrets.compare_digest` aliases;
- cross-function or cross-file flows;
- the separate oversized-header resource-consumption control introduced by Newsdom PR #497;
- exception handlers that deliberately catch the comparator error;
- other APIs with their own text/byte contracts.

Expand the detector only with a new independently reproduced vulnerable source and reviewed negative oracle.

## APA 7 references

MITRE Corporation. (2026). *CWE-20: Improper input validation* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/20.html

MITRE Corporation. (2026). *CWE-248: Uncaught exception* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/248.html

Python Software Foundation. (2026). *hmac — Keyed-hashing for message authentication* (Python 3.14.6 documentation). https://docs.python.org/3/library/hmac.html
