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
| JavaScript JSON password type-validation before password crypto | built-in `javascript-json-password-string-coercion-before-hash` and `javascript-json-password-untyped-verify-fallback` rules | active-PR #945; source-authoritative ScopeWeave replay, production `_scan_file` oracle, CWE-1287 boundary |
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

## Password type-validation detector family

AppGuardrail issues `#770` and `#772` are duplicate cancelled workflow-event provenance from ScopeWeave PR `#386`; they are not vulnerability proof. The detector obligation is instead bound to the independently reviewed source pair:

- vulnerable ScopeWeave revision `a756b7e3cf486cba0930c1a482c6a30e0df958f5`, with `server/app.mjs` blob `926d528d17b7ae39ab89001657a21f7ef30af743` and `server/auth.mjs` blob `3d0b171fb2d5049f010c405f051409a849840b26`;
- reviewed fixed revision `bd9a51584f1cf37f4f4446022a90775a20152edf`, with `server/app.mjs` blob `13d95e5dfa0719451a5b4a6d952467994172b79a` and `server/auth.mjs` blob `a16a7281b3da4683eea85263fea929dd9483e9df`;
- RED-first regression and production scanner replay in `tests/test_javascript_password_type_validation_rules.py`;
- packaged rules in `scanner/rules/password_type_validation.yml`;
- detector contract, limitations, remediation, and APA 7 references in `docs/detectors/javascript-password-type-validation.md`.

The two bounded signatures cover only the observed Hono JSON-body shapes: coercive `String(password).length` followed by hashing of the original untyped value, and `verifyPassword(password || '', ...)` without a visible string-type guard. Their regex regions terminate at the current handler boundary so a JSON source in one adjacent route cannot be paired with a password-crypto sink in another route. Fixed explicit type guards, schema-validated paths, other frameworks, helper aliases, and cross-file flows remain outside this detector family rather than being inferred from the cancelled collector events. Current CWE 4.20 defines CWE-1287 as failing to validate that input is actually of the expected type, while current Node.js `crypto.scryptSync` documentation restricts password inputs to supported string/binary-view types; ordinary JSON arrays and objects are not accepted by that API contract.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
