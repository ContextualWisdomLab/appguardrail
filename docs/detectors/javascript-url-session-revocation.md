# JavaScript URL-token session-revocation detector

**Status:** Source-derived detector slice  
**Rule ID:** `javascript-url-session-token-without-revocation`  
**Weakness mapping:** CWE-613, applied with review  
**Collected source family:** ScopeWeave PR #397; AppGuardrail collector issue #775

## Buyer-visible protection

Self-contained session JWTs can remain cryptographically valid after the application has intentionally revoked the corresponding login state. ScopeWeave already enforces a database-backed `token_version` check in its normal bearer middleware, but the collected source snapshot exposed alternate query-token transports whose calendar and stream routes called `verifyToken` directly. A credential revoked by logout-all, password change, or another token-version bump could therefore continue authorizing those routes until JWT expiration.

The detector reports the two exact source shapes where a URL-token endpoint uses the signature/expiry-only verifier and immediately continues after its `try` block. It remains negative when the route calls the reviewed `verifySessionJwt` helper or when an independently authored route performs the equivalent database-backed token-version check inline.

## Source-authoritative evidence

The cancelled Strix workflow in AppGuardrail issue #775 is provenance only. Detector efficacy comes from immutable ScopeWeave source objects:

- vulnerable base head: `a756b7e3cf486cba0930c1a482c6a30e0df958f5`;
- vulnerable `server/app.mjs` blob: `926d528d17b7ae39ab89001657a21f7ef30af743`;
- reviewed fixed head: `5ed7fa125bcf63df4bb548d8bc244ac4ddf0054c`;
- fixed `server/app.mjs` blob: `b5ea69b272f571c1fd3b677c07b636f5f7ca610e`.

The vulnerable snapshot contains two incomplete session-verification paths:

1. `/api/projects/:id/calendar.ics` obtains a `?token=` value and executes `verifyToken(raw).sub` before project authorization;
2. `/api/projects/:id/stream` obtains a `?token=` value and executes `verifyToken(token)` before project authorization.

The attachment-view route in the same vulnerable blob already checks `token_version` after `verifyToken`, so this detector deliberately does not flag that endpoint. The reviewed repair centralizes the correct behavior in `verifySessionJwt`, which verifies the JWT, loads the current user row, compares the token `tv` claim with the current database `token_version`, and rejects missing or stale sessions before authorization.

## Detection contract

The lightweight rule contains two route-specific variants under one weakness identity. Each requires:

- the exact source-derived URL-token route family (`calendar.ics` or `/stream`);
- `c.req.query('token')` evidence;
- the exact direct `verifyToken(raw)` or `verifyToken(token)` call;
- the source-derived immediate `try { ... verifyToken ... } catch` shape, which distinguishes the vulnerable path from an inline revocation check performed after JWT decoding.

Each multiline expression is route- and character-bounded. File-level prefilters include no commas so AppGuardrail's lightweight inline-list loader preserves the intended tokens.

## Remediation boundary

All transports that accept a session credential must enforce the same authoritative server-side session state before using the credential for access control. A correct repair may call a shared revocation-aware verifier or perform the same database-backed invalidation check inline before the protected operation.

The OWASP Session Management Cheat Sheet requires server-side invalidation when sessions expire or users log out and identifies password changes as a risk event requiring renewed authentication. OWASP ASVS 5.0 V7.2.1 requires session-token verification through a trusted backend service. These requirements support centralizing verification so alternate transports cannot bypass the application's revocation state.

CWE-613 is the closest current CWE 4.20 mapping for reuse of old session credentials after intended invalidation, but MITRE marks it `ALLOWED-WITH-REVIEW` and notes that the entry is under reconsideration because it has historically combined timeout and logout-invalidation concepts. AppGuardrail therefore records the mapping with that qualification rather than treating CWE-613 as an exact universal taxonomy for every revocation defect.

## Declared limitations

This is not a general session-management or JavaScript interprocedural dataflow engine. It intentionally does not claim coverage for:

- route names or variable names outside the two collected source shapes;
- cookie or header transports that use different authentication middleware;
- revocation implemented in a caller, framework middleware, database trigger, or remote identity service;
- PAT/API-key revocation semantics;
- refresh-token rotation, token theft through URLs, referrer leakage, access logs, or browser history;
- idle/absolute timeout policy;
- the planned replacement of full query-string JWTs with narrowly scoped ephemeral grants;
- authentication defects where the decoded token never reaches project authorization.

Broaden the detector only from another independently reproduced vulnerable source and reviewed negative oracle.

## APA 7 references

MITRE Corporation. (2026). *CWE-613: Insufficient session expiration* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/613.html

OWASP Foundation. (2026). *Session management cheat sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

OWASP Foundation. (2025). *OWASP application security verification standard 5.0: V7.2 Fundamental session management security*. https://cornucopia.owasp.org/taxonomy/asvs-5.0/07-session-management/02-fundamental-session-management-security
