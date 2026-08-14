# JavaScript URL-Session Revocation Bypass

## Status

Active bounded detector contract for a ScopeWeave session-lifecycle weakness collected through AppGuardrail issue `#775`. The cancelled Strix job is retained only as provenance. The detector claim is grounded in source code that is independently observable on ScopeWeave's protected `develop` branch and in the reviewed but unmerged repair from ScopeWeave PR `#397`.

## Source-authoritative replay

- Source repository: `ContextualWisdomLab/scopeweave`
- Collector provenance: AppGuardrail issue `#775`, sourced from ScopeWeave PR `#397`
- Historical vulnerable revision: `a756b7e3cf486cba0930c1a482c6a30e0df958f5`
- Historical vulnerable `server/app.mjs` blob: `926d528d17b7ae39ab89001657a21f7ef30af743`
- Protected ScopeWeave `develop` observed on 2026-08-14: `b88e66e81e9701404d29a0f5de4f58573ceee14f`
- Protected `server/app.mjs` blob at that revision: `450be87886a9668fbe39b427aaeb08fc3438dc5d`
- Reviewed repair candidate: ScopeWeave PR `#397`, final head `5ed7fa125bcf63df4bb548d8bc244ac4ddf0054c`
- Repair-candidate `server/app.mjs` blob: `b5ea69b272f571c1fd3b677c07b636f5f7ca610e`
- PR `#397` was closed without merge, so its code is a fixed negative oracle rather than protected-branch truth.

At the protected revision above, normal bearer authentication verifies a JWT and then checks the referenced user's database-backed `token_version`. The calendar and event-stream routes, however, also accept `?token=...` and call `verifyToken(...)` directly before using the JWT subject. That makes signature validity sufficient on those query-token paths even after the normal session model has revoked older generations.

PR `#397` introduced a shared `verifySessionJwt(token)` boundary that verifies the JWT, loads the user, compares the token `tv` claim with the current database `token_version`, and then uses that boundary from the bearer, calendar, stream, and attachment paths. Because that PR did not merge, AppGuardrail treats it only as the independently reviewed fixed negative for this detector family.

## Detector contract

Rule `javascript-url-session-jwt-revocation-bypass` reports only the source-derived Hono shape where:

1. a GET route obtains a credential from `c.req.query('token')`;
2. the same bounded route directly calls one of the exact collected forms `uid = verifyToken(raw).sub` or `user = verifyToken(token)`; and
3. no revocation-aware helper substitutes for that direct signature-only verification.

The two exact direct-call forms intentionally avoid matching the attachment route in the historical source, where the code already performed an inline `token_version` check after `verifyToken`.

The rule is `HIGH`, high confidence, and maps to `CWE-613` and `OWASP A07:2025`.

## Security boundary

CWE-613 describes insufficient session expiration as permitting reuse of old session credentials and explicitly allows real-world vulnerability mapping with careful review. OWASP Top 10:2025 maps CWE-613 to A07 Authentication Failures. OWASP's Session Management Cheat Sheet states that server-side invalidation is mandatory when a user logs out or a session expires, while the REST Security Cheat Sheet warns that JWT validity can diverge from current server-side session state after explicit termination.

In the observed source, the security property is not merely token signature validity. The application already defines a newer server-side session-generation value (`token_version`) and uses it on the normal bearer path. A query-token route that skips that check therefore bypasses an intended revocation boundary.

## Remediation

- Route every session JWT transport through one revocation-aware verification function.
- Verify the JWT signature and expiry, then verify that the referenced account still exists and that the token's generation/version equals the current server-side session version.
- Prefer narrow, short-lived, purpose-bound URL grants instead of full session JWTs where headers are unavailable.
- Keep URL credentials out of logs and referrers where possible, and make their lifetime/revocation semantics explicit.
- Preserve an inline generation check only when it is semantically equivalent to the shared session-verification boundary and is covered by regression tests.

## Deliberate limitations

This detector is intentionally not a general session-taint or JWT analyzer. It does not claim to detect:

- bearer-only routes that never accept a query token;
- query-token schemes that are independent PATs, API keys, or purpose-scoped grants;
- cross-function flows where query-token extraction and JWT verification occur in different modules;
- applications without a server-side revocation/session-generation mechanism;
- direct `verifyToken` calls followed by a semantically complete inline revocation check; or
- other frameworks, route syntaxes, or JWT libraries not represented by the collected source shape.

Those require separate source-backed detector obligations rather than broadening this rule until it becomes a generic keyword heuristic.

## APA 7 references

MITRE. (2026, April 30). *CWE-613: Insufficient session expiration (CWE Version 4.20).* Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/613.html

Open Worldwide Application Security Project. (2025). *A07:2025 Authentication failures.* OWASP Top 10:2025. https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/

Open Worldwide Application Security Project. (n.d.). *REST security cheat sheet.* OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html

Open Worldwide Application Security Project. (n.d.). *Session management cheat sheet.* OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
