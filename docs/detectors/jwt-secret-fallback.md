# Hardcoded JWT secret fallback detector

**Status:** Source-derived detector slice  
**Rule ID:** `javascript-jwt-hardcoded-secret-fallback`  
**Primary weakness classes:** CWE-321, CWE-798  
**Collected issue family:** AppGuardrail issues #462, #463, #468, and #469  
**Source change:** `ContextualWisdomLab/scopeweave` PR #387; vulnerable head `7a6ff367a43a8711fc97d124d0bed5dad8941b7d` and blob `3d0b171fb2d5049f010c405f051409a849840b26`; reviewed fixed head `37289072bd3039fcca3f113e5707e7a278a3a9b1` and blob `5893dd511f5a73fa8e595728e68f6e84d4011c45`

## Buyer-visible protection

A server that silently substitutes a source-controlled string when a JWT signing environment variable is absent can mint and verify authentication tokens with the same discoverable key in every affected deployment. A warning does not close that boundary: the process remains available and continues signing tokens. The detector reports the collected Node.js HS256 source shape as a deploy-blocking CRITICAL finding so missing production configuration fails in CI rather than becoming a shared authentication bypass.

## Detection contract

The lightweight detector requires all of the following evidence in one JavaScript or TypeScript file:

1. `const`, `let`, or `var` assigns a local key variable from `process.env.NAME` or `process.env["NAME"]`;
2. `||` or `??` supplies a hardcoded string of at least eight characters;
3. the same variable is later passed as the key argument to `createHmac("sha256", key)`;
4. the sink occurs within a bounded 12,000-character window;
5. the variable is not reassigned before the sink.

The rule is protected by the file-level prefilter `process.env`, `createHmac`, and `HS256`. The prefilter avoids evaluating the multiline expression for unrelated source files; the regex then binds the environment-derived variable to the actual HMAC key argument.

## Source-authoritative evidence corpus

`tests/test_jwt_secret_fallback_rules.py` preserves independent evidence rather than trusting the collected workflow label:

- the exact ScopeWeave environment fallback and HS256 HMAC use;
- the reviewed fail-closed source with no literal fallback;
- the equivalent nullish-coalescing fallback;
- a runtime-random fallback negative;
- a literal fallback that never reaches a signing sink;
- the production `_scan_file` finding envelope, including line, severity, category, confidence, CWE, and OWASP metadata;
- immutable repository, head, and blob identifiers for both sides of the source change.

## Remediation boundary

The application must not replace a missing token-signing key with a source-controlled default. A safe repair should:

1. obtain the key from managed secret configuration;
2. fail process startup before serving requests when the key is absent, unresolved, or too weak for the selected algorithm;
3. validate the exact value used by every signing and verification path;
4. rotate any default key that may have reached a deployment;
5. invalidate tokens that could have been signed with the exposed key;
6. keep test-only keys in explicit test configuration rather than production fallbacks.

RFC 8725 requires sufficient cryptographic-key entropy and states that human-memorable passwords must not be used directly as keyed-MAC keys such as HS256. CWE-321 identifies hardcoded cryptographic keys as a specific weakness, while CWE-798 covers the broader hardcoded-credential boundary. OWASP A07:2021 advises against shipping or deploying default credentials.

## Declared limitations

This is not a general JavaScript dataflow engine. It intentionally does not claim coverage for:

- signing keys passed through helper functions, objects, arrays, or dependency injection;
- environment APIs other than the tested `process.env` forms;
- HMAC algorithms or JWT libraries that do not expose the tested `createHmac("sha256", key)` shape;
- asymmetric JWT keys;
- literals constructed from multiple expressions;
- cross-file assignment and signing flows;
- weak environment-provided keys without a hardcoded fallback.

Those cases require separate source-derived detector obligations or structural interprocedural analysis. Expanding this regex without a new positive source and independent fixed negative is prohibited.

## APA 7 references

MITRE Corporation. (2026). *CWE-321: Use of hard-coded cryptographic key* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/321.html

MITRE Corporation. (2026). *CWE-798: Use of hard-coded credentials* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/798.html

OWASP Foundation. (2021). *A07:2021—Identification and authentication failures*. https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/

Sheffer, Y., Hardt, D., & Jones, M. (2020). *JSON Web Token best current practices* (RFC 8725). RFC Editor. https://doi.org/10.17487/RFC8725
