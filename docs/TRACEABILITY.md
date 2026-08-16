# AppGuardrail Requirements, Detection, and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-08-16

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
| Node.js authentication password type validation before `scryptSync` | built-in `javascript-auth-scrypt-unvalidated-password-type` family | issue #948 active-PR obligation; exact ScopeWeave vulnerable/fixed commit→tree→`server/auth.mjs` blob mappings, immutable replay fixtures, structural variants, and production `_scan_file` regressions required before promotion |
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

## Scrypt password type-boundary traceability contract

The source-backed detector obligation in issue #948 is separate from the collector workflow status that first surfaced the source change. Its evidence chain is:

1. collector issues #729 and #732 preserve ScopeWeave PR #394 event provenance only;
2. vulnerable source is pinned to ScopeWeave head `a756b7e3cf486cba0930c1a482c6a30e0df958f5`, tree `0d05f369c4648b390a280d11e60bce2a6294d5e5`, where `server/auth.mjs` resolves to blob `3d0b171fb2d5049f010c405f051409a849840b26`;
3. reviewed fixed source is pinned to head `644e9fc5cb3adfb96e2948152f92c61f8661e6d3`, tree `84c85ea25ffa11e94c80ca3d1d41365312857af6`, where `server/auth.mjs` resolves to blob `a16a7281b3da4683eea85263fea929dd9483e9df`;
4. the required provenance regression resolves each pinned commit through GitHub's Git commit/tree API, requires exactly one `server/auth.mjs` path mapping to the declared blob, and then verifies the local replay fixture has that same Git blob object ID;
5. `hashPassword` and `verifyPassword` are independently tested source-shape variants under one CWE-1287 family, including TypeScript parameter annotations, nested blocks, and non-terminating type comparisons;
6. the fixed source, safe normalization, fail-closed pre-sink rejection, and unrelated KDF helper are negative oracles;
7. the production `_scan_file` entrypoint must emit normalized HIGH findings on the vulnerable replay and none on the reviewed repair;
8. only exact-head protected checks plus independent review can promote the family to `implemented-main`.

Cancelled or failed workflow/reviewer jobs are never detector efficacy evidence and are not sufficient to satisfy any step above.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.