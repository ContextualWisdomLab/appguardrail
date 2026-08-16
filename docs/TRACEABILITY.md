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
| Python required-authentication secret fail-open | built-in candidate `python-auth-secret-missing-fail-open` rule | candidate branch only; not `implemented-main` until protected merge plus exact protected-head evidence |
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

## Missing authentication secret traceability contract

The branch-local `python-auth-secret-missing-fail-open` candidate is grounded in source code rather than collector workflow conclusions. Its traceability chain is:

1. source repository `ContextualWisdomLab/newsdom-api`;
2. vulnerable head `04491c0e9ac38b9f793029683cebfb8210ccfadd`, `src/newsdom_api/main.py` blob `4efdad56ed78ed5c0158cdf0d746aedfe72604fe`;
3. reviewed fix PR #539 head `e22bb76bcf821dfa21eb83938a474c6cf3e7c1e8`, protected merge `76417bd240398c1a4bf2f6c65d693ea523b179d0`, fixed blob `f61aafc2d6592f4a84c7b02b50cfe4a972623463`;
4. packaged candidate rule `scanner/rules/fail_open_auth_secret.yml` and regression module `tests/test_fail_open_auth_secret_rules.py`;
5. production `_scan_file` replay that must emit one normalized positive finding for the vulnerable source and no finding for the protected fixed source; and
6. CWE-306 plus OWASP Top 10:2025 A07 as the standards classification boundary.

The vulnerable source returns successfully from an authentication guard when its required server token is absent. The protected fix permits bypass only through an explicit `AuthenticationMode.DISABLED` development profile and otherwise returns a controlled service-unavailable response when the token is missing. The candidate deliberately does not use the cancelled/failed NewsDOM collector events as vulnerability proof, and it does not become protected shipped truth until normal review, exact-head checks, merge, and protected-head verification complete.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

The missing-authentication-secret candidate is classified against MITRE CWE 4.20 CWE-306 and OWASP Top 10:2025 A07; its detector-specific doctoring also records OWASP API Security Top 10:2023 API2 as supporting microservice authentication guidance. Those references define the weakness/control class, while the exact NewsDOM vulnerable/fixed Git objects define detector efficacy evidence.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
