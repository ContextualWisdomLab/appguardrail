# Python HMAC Unicode Header DoS

## Status

Active bounded detector contract for the NewsDOM bearer-authentication weakness family. AppGuardrail's collected workflow failures are provenance only; detector truth is grounded in the exact vulnerable source and the later protected fix.

## Source-authoritative replay

- Source repository: `ContextualWisdomLab/newsdom-api`
- Vulnerable source base: `04491c0e9ac38b9f793029683cebfb8210ccfadd`
- Vulnerable `src/newsdom_api/main.py` blob: `4efdad56ed78ed5c0158cdf0d746aedfe72604fe`
- Early generated fix examples: PR `#495` head `24dd60aa076893513fe1fe4de801350f1f6714ee` and PR `#499` head `0c1048478901acaaaad14c052d46594d80a649cd`
- Authoritative reviewed fix: merged PR `#539`, head `e22bb76bcf821dfa21eb83938a474c6cf3e7c1e8`
- Protected merge commit: `76417bd240398c1a4bf2f6c65d693ea523b179d0`
- Fixed `src/newsdom_api/main.py` blob: `f61aafc2d6592f4a84c7b02b50cfe4a972623463`
- Retained AppGuardrail collector provenance: issues `#796`, `#802`, `#804`, `#807`, `#808`, and `#811`, covering the duplicate PR `#495`, `#497`, and `#499` workflow-event family. Cancelled or failed workflow conclusions are not used as vulnerability proof.

The vulnerable function accepted `authorization` as a FastAPI `Header()` string, assigned `provided = authorization or ""`, and passed `provided` and `expected` directly to `hmac.compare_digest`. Python documents that string operands for `compare_digest` are ASCII-only. A non-ASCII attacker-controlled header can therefore raise `TypeError` before the application reaches its normal `401` response.

The protected fix in PR `#539` changes the boundary rather than merely catching the exception: it reads raw authorization bytes, enforces a finite byte budget, parses a byte-oriented Bearer credential, and compares bytes against `token.encode("utf-8")`.

## Detector contract

Rule `python-hmac-compare-digest-unicode-header-dos` reports only the bounded source shape where:

1. an `authorization` parameter is declared from FastAPI `Header()` as a Python string;
2. the function derives `provided = authorization or ""`; and
3. the same function forwards the raw string variables directly as `hmac.compare_digest(provided, expected)`.

The rule is `MEDIUM`, high confidence, and maps to `CWE-248` because the concrete consequence is an uncaught `TypeError` on an attacker-influenced request path. `CWE-248` explicitly permits vulnerability mapping and identifies crash/availability impact from uncaught exceptions. OWASP Top 10:2025 maps CWE-248 into `A10:2025 - Mishandling of Exceptional Conditions`.

## Remediation

- Prefer a byte-oriented HTTP authentication boundary when the framework exposes raw header bytes.
- Bound untrusted header size before normalization or constant-time comparison.
- If the application must use strings, encode both operands to bytes before `compare_digest` and handle encoding failures at the boundary.
- Preserve one controlled authentication-failure response instead of allowing library exceptions to determine the HTTP result.

## Deliberate limitations

This is not a generic Python exception or HMAC analyzer. It intentionally does not claim to detect:

- generic `compare_digest(str, str)` calls where both strings are known ASCII digests;
- headers obtained through a different framework or helper;
- cross-function aliases from a header source to the comparison sink;
- direct byte-valued comparisons;
- source strings encoded before comparison; or
- arbitrary Unicode/encoding weaknesses unrelated to the observed authentication path.

Those require separate source-backed obligations rather than broadening this rule into a noisy keyword check.

## APA 7 references

MITRE. (2026, April 30). *CWE-248: Uncaught exception (CWE Version 4.20).* Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/248.html

Open Worldwide Application Security Project. (2025). *A10:2025 Mishandling of exceptional conditions.* OWASP Top 10:2025. https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/

Python Software Foundation. (2026). *hmac — Keyed-hashing for message authentication (Python 3.14.6 documentation).* https://docs.python.org/3/library/hmac.html
