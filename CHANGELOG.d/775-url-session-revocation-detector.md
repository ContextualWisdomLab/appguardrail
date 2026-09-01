### Security

- Added the bounded `javascript-url-session-revocation-bypass` SAST rule for Hono GET routes that accept a session JWT from `c.req.query('token')` and use the collected direct `verifyToken(...)` forms without the application's database-backed session-generation check.
- Retained AppGuardrail issue `#775` as collector provenance only and grounded detector efficacy in ScopeWeave source: historical vulnerable revision `a756b7e3cf486cba0930c1a482c6a30e0df958f5`, protected `develop` observed at `b88e66e81e9701404d29a0f5de4f58573ceee14f`, and the reviewed-but-unmerged PR `#397` fixed candidate `5ed7fa125bcf63df4bb548d8bc244ac4ddf0054c`.
- Mapped the concrete old-session reuse path to `CWE-613` and `OWASP A07:2025`, with source-derived negative boundaries for inline revocation checks, bearer-only routes, and the reviewed `verifySessionJwt` repair. Complete explicit CWE/OWASP references now remain authoritative instead of inheriting unrelated category-default taxonomy entries.
