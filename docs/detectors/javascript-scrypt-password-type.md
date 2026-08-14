# JavaScript scrypt password input-type detector

**Status:** Source-derived detector slice  
**Rule ID:** `javascript-auth-scrypt-unvalidated-password-type`  
**Primary weakness:** CWE-1287  
**Secondary consequence/control failure:** CWE-248  
**Collected source family:** AppGuardrail collector issues #729 and #732; ScopeWeave PR #394, later superseded by the security consolidation in ScopeWeave PR #386

## Buyer-visible protection

Authentication endpoints commonly deserialize JSON into dynamically typed JavaScript values. Node.js `crypto.scryptSync` accepts a password as a string or supported byte-oriented view, and its current documentation states that invalid argument types cause an exception. Passing an unvalidated JSON object or array directly into a password hashing or verification sink therefore crosses an input-type boundary before the cryptographic operation can safely proceed.

This detector catches the exact bounded source shape observed in ScopeWeave: `hashPassword` or `verifyPassword` accepts a password parameter and passes that same parameter directly to `scryptSync` before an explicit string-type guard or before normalizing to a separate safe value.

## Source-authoritative evidence

The detector does not infer vulnerability from a cancelled Strix/OpenCode workflow. Those collector events are provenance only. Its positive and negative oracles are immutable source objects:

- vulnerable repository: `ContextualWisdomLab/scopeweave`;
- vulnerable head: `a756b7e3cf486cba0930c1a482c6a30e0df958f5`;
- vulnerable `server/auth.mjs` blob: `3d0b171fb2d5049f010c405f051409a849840b26`;
- reviewed fixed head: `644e9fc5cb3adfb96e2948152f92c61f8661e6d3`;
- reviewed fixed `server/auth.mjs` blob: `a16a7281b3da4683eea85263fea929dd9483e9df`.

The reviewed source fixes both tested paths: `hashPassword` derives a separate string value before calling `scryptSync`, while `verifyPassword` rejects non-string input before the sink.

## Detection contract

The lightweight detector contains two variants under one weakness identity:

1. `hashPassword(parameter)` directly passes `parameter` to `scryptSync` without a preceding `typeof parameter ... "string"` comparison;
2. `verifyPassword(parameter, ...)` directly passes the same parameter to `scryptSync` without the preceding comparison.

Both signatures are function- and character-bounded. File-level prefilters require `scryptSync(` plus the corresponding password-function declaration so unrelated key-derivation code is skipped before multiline regex evaluation.

## Remediation boundary

Validate or normalize authentication input before calling the cryptographic API. For verification, rejecting unsupported input types is preferable to coercing arbitrary JSON because coercion can collapse different values into the same string representation. For a hashing path whose product contract deliberately normalizes invalid values, derive a separate supported value before the sink and keep the caller validation contract explicit.

## Declared limitations

This is not a JavaScript interprocedural type/dataflow engine. It intentionally does not claim coverage for:

- custom password helper names other than the two source-derived functions;
- destructured or aliased password parameters;
- type guards implemented in callers or separate helper functions;
- asynchronous `crypto.scrypt`;
- other password/KDF APIs such as Argon2 or PBKDF2;
- supported `Buffer`, `TypedArray`, or `DataView` password inputs;
- exception handling around the scrypt call;
- arbitrary resource-exhaustion or generic DoS conditions.

Expand the family only from an independently reproduced vulnerable source plus a reviewed negative oracle.

## APA 7 references

MITRE Corporation. (2026). *CWE-1287: Improper validation of specified type of input* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/1287.html

MITRE Corporation. (2026). *CWE-248: Uncaught exception* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/248.html

OpenJS Foundation. (2026). *Crypto: Node.js v26.5.1 documentation*. https://nodejs.org/api/crypto.html
