# AppGuardrail Requirements, Detection, and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-08-14

| Requirement / security class | Detector/control boundary | Evidence maturity |
|---|---|---|
| built-in deterministic scanning | `scanner.py`, rule adapters, normalized findings | implemented-main |
| optional Trivy/Bandit/Ruff/Semgrep/ZAP | external-engine adapters | implemented-main when tool present; capability explicit |
| JSON/SARIF findings | reporting serializers | implemented-main |
| deploy gate/exclusions | gate policy | implemented-main |
| safe deterministic autofix | fix engine | implemented-main for supported transforms only |
| multi-tenant scan/history/drift/API keys | control plane | implemented-main |
| webhook config/notification | control plane/network boundary | implemented-main; storage-boundary SSRF hardening integrated through PR #924 |
| buyer/founder/agency/fix-pack reports | report modules | implemented-main |
| CycloneDX SBOM | SBOM module | implemented-main |
| organization buyer evidence | org evidence aggregator | implemented-main |
| RCA-first feasibility scheduler | CI/agent policy | implemented-main |
| every retained issue claim mapped to executable detector obligation | issue-detection audit | PR #911 active-PR |
| authenticated workflow-result detector evidence | issue-detection audit workflow evidence | PR #911 active-PR |
| automatic scanner detection of unsafe stored-webhook SSRF pattern | built-in `python-stored-ssrf-webhook-url` rule | implemented-main through PR #910 for tested Python `set_webhook` direct and one-hop persistence flows; bounded scope |
| URL-carried session JWT bypasses token-version revocation | built-in `javascript-url-session-jwt-revocation-bypass` rule | active-PR #947; protected ScopeWeave source remains vulnerable, reviewed unmerged fix is the negative oracle, CWE-613/A07:2025 boundary |
| structural Semgrep-style `pattern:` execution by lightweight engine | built-in scanner | not implemented unless a real structural matcher is added; fixtures are not execution |

## Promotion rules

- `implemented-main` requires source/tests on protected `develop`, not an issue/PR description.
- `active-PR` becomes current only after merge plus fresh protected-head required evidence.
- External-engine capability must name the engine and availability; normalization does not convert it into a built-in detector.
- A prevention/hardening change does not automatically promote the matching scanner-detection row; PR #924 and PR #910 were verified and promoted independently.
- An issue registry mapping cannot promote an obligation unless actual detector execution derives its result from independent/closed evidence.

## Issue #911 traceability contract

When PR #911 is accepted, the authoritative obligation system should preserve issue number/claim identity, detector family, evidence fixture/workflow provenance, execution result, and detector rule/finding evidence. Deduplicating equivalent incidents into one detector family is allowed; dropping a retained claim through an exclusion/waiver list is not.

## SSRF traceability contract

For stored webhook/callback SSRF, trace separately:

1. application prevention at configuration storage;
2. execution-time URL/DNS/IP/redirect/egress validation;
3. AppGuardrail scanner rule capable of finding missing prevention in target code;
4. positive vulnerable fixture;
5. fixed negative fixture;
6. control-plane self-regression;
7. exact-head security/review evidence.

Current protected-branch evidence keeps those controls distinct: PR #924 supplies the fail-closed webhook storage boundary, and PR #910 supplies the packaged `python-stored-ssrf-webhook-url` detector plus focused regression corpus. Neither control expands the detector beyond its declared source/sink and flow contract.

## URL-session revocation detector family

AppGuardrail issue `#775` is a cancelled Strix workflow event and therefore only a provenance pointer. The detector obligation is grounded in ScopeWeave source, where normal bearer authentication checks database-backed `token_version` revocation while URL query-token routes independently call raw JWT verification.

- historical vulnerable ScopeWeave revision `a756b7e3cf486cba0930c1a482c6a30e0df958f5`, `server/app.mjs` blob `926d528d17b7ae39ab89001657a21f7ef30af743`;
- protected ScopeWeave `develop` observed 2026-08-14 at `b88e66e81e9701404d29a0f5de4f58573ceee14f`, blob `450be87886a9668fbe39b427aaeb08fc3438dc5d`, where the calendar and stream GET query-token paths still use `verifyToken` directly;
- reviewed ScopeWeave PR #397 final head `5ed7fa125bcf63df4bb548d8bc244ac4ddf0054c`, blob `b5ea69b272f571c1fd3b677c07b636f5f7ca610e`, retained only as a fixed negative because PR #397 closed without merge;
- RED-first source replay and production `_scan_file` regression in `tests/test_url_session_revocation_rules.py`;
- packaged `javascript-url-session-jwt-revocation-bypass` rule in `scanner/rules/url_session_revocation.yml`;
- detector doctoring in `docs/detectors/javascript-url-session-revocation.md`.

The HIGH detector is intentionally limited to the collected direct GET-route shapes where `c.req.query('token')` feeds raw `verifyToken` without the token-version session validation used by the normal bearer path. Inline `token_version` checks, bearer-only verification, and the reviewed `verifySessionJwt` replacement are negative oracles. It does not infer revocation semantics across helper files, different frameworks, opaque session stores, or unrelated URL tokens. CWE 4.20 CWE-613 defines insufficient session expiration as permitting reuse of old session credentials, and OWASP Top 10:2025 A07 covers authentication failures; OWASP session-management guidance treats a session token as equivalent to the authentication strength that established it and requires the authentication/session-management boundary to remain linked.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
