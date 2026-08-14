# JavaScript JSON Password Type Validation

## Status

Active detector contract for the source-derived ScopeWeave password-boundary weakness family. Collected workflow failures are provenance only; the security claim is grounded in the exact vulnerable/fixed source revisions below.

## Source-authoritative replay

- Source repository: `ContextualWisdomLab/scopeweave`
- Source PR: `#386`
- Vulnerable revision: `a756b7e3cf486cba0930c1a482c6a30e0df958f5`
- Vulnerable `server/app.mjs` blob: `926d528d17b7ae39ab89001657a21f7ef30af743`
- Vulnerable `server/auth.mjs` blob: `3d0b171fb2d5049f010c405f051409a849840b26`
- Reviewed fixed revision: `bd9a51584f1cf37f4f4446022a90775a20152edf`
- Fixed `server/app.mjs` blob: `13d95e5dfa0719451a5b4a6d952467994172b79a`
- Fixed `server/auth.mjs` blob: `5893dd511f5a73fa8e595728e68f6e84d4011c45`
- Collected AppGuardrail provenance: issues `#770` and `#772` from cancelled Strix workflow events on ScopeWeave PR `#386`.

The vulnerable signup route accepted `password` from an untyped JSON body, validated `String(password).length`, and then forwarded the original `password` value to `hashPassword`. The vulnerable login route forwarded `password || ''` to `verifyPassword` without first proving that `password` was a string. The helper layer then passed the value to Node.js `scryptSync`.

The reviewed fix rejects non-string values at the route boundary and also makes the helper boundary fail closed. Detector efficacy is therefore established from the source delta and fixed negative, not from the cancelled workflow conclusion.

## Detector contract

### `javascript-json-password-string-coercion-before-hash`

Detect the bounded source shape:

1. a password originates from a Hono-style `c.req.json()` body;
2. `String(password).length` is used as the validation surrogate;
3. no explicit `typeof password ... 'string'` check appears in the bounded path; and
4. the original `password` value is later forwarded to `hashPassword(password)`.

### `javascript-json-password-untyped-verify-fallback`

Detect the bounded source shape:

1. a password originates from `c.req.json()`;
2. no explicit string-type guard appears in the bounded path; and
3. `verifyPassword(password || '', ...)` forwards truthy objects/arrays without narrowing them to the crypto helper's supported type.

Both rules are `MEDIUM`, high-confidence, source-derived SAST rules mapped to `CWE-1287`.

## Security boundary

MITRE CWE-1287 defines the root cause as failure to validate that input is of the expected type. Node.js documents `crypto.scryptSync` password inputs as `string`, `Buffer`, `TypedArray`, or `DataView`; ordinary JSON arrays and objects are not part of that accepted contract. At an HTTP JSON boundary, accepting arbitrary structured values and relying on string coercion or truthiness therefore creates a type-validation gap before the cryptographic operation.

## Remediation

- Reject non-string password values before length, complexity, hashing, or verification logic.
- Prefer an allowlisted schema/type validator at the HTTP boundary.
- Keep the downstream password helper fail closed for callers that bypass the route validator.
- Return application-controlled authentication/validation errors rather than allowing crypto-library type errors to define request behavior.

## Deliberate limitations

This detector is intentionally not a general JavaScript taint engine. It does not claim to detect:

- password sources other than the bounded `c.req.json()` shape;
- helper names other than `hashPassword` and `verifyPassword`;
- cross-file aliasing or wrapper-mediated flows;
- schema libraries whose successful parse is not visible in the same source region;
- direct `scrypt`/Argon2/bcrypt calls under unrelated APIs; or
- every possible JavaScript coercion/type-confusion weakness.

Those cases require separate detector obligations rather than widening this source-derived signature until false positives become unbounded.

## APA 7 references

MITRE. (2026, April 30). *CWE-1287: Improper validation of specified type of input (CWE Version 4.20).* Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/1287.html

Node.js contributors. (2026). *Crypto: `crypto.scryptSync(password, salt, keylen[, options])` (Node.js v26.5.1 documentation).* Node.js. https://nodejs.org/api/crypto.html
