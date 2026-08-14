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
| raw Unicode bearer input passed to string `hmac.compare_digest` | built-in Python bearer-HMAC rule in `scanner/rules` | active-PR #946; NewsDOM vulnerable/fixed source pair, production `_scan_file` replay, CWE-248/A10:2025 boundary |
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

## Unicode bearer HMAC comparison detector family

AppGuardrail issues `#796`, `#802`, `#804`, `#807`, `#808`, and `#811` are duplicate workflow-event provenance. Their workflow outcomes are not used as vulnerability proof. The detector obligation is bound to the independently inspectable NewsDOM source transition:

- vulnerable NewsDOM revision `04491c0e9ac38b9f793029683cebfb8210ccfadd`, `src/newsdom_api/main.py` blob `4efdad56ed78ed5c0158cdf0d746aedfe72604fe`;
- reviewed fixed PR #539 head `e22bb76bcf821dfa21eb83938a474c6cf3e7c1e8`, protected merge `76417bd240398c1a4bf2f6c65d693ea523b179d0`, fixed blob `f61aafc2d6592f4a84c7b02b50cfe4a972623463`;
- RED-first and production scanner regression corpus in the PR #946 test file;
- packaged Python detector rule and its bounded prefilters;
- detector doctoring with remediation, explicit false-positive/false-negative boundaries, and APA 7 references.

The matched source shape is intentionally narrow: a FastAPI `Header()`-sourced authorization string reaches `hmac.compare_digest` as a Python `str` without an intervening byte conversion or ASCII restriction. Python 3.14.6 documents string `compare_digest` operands as ASCII-only; the reviewed fix converts the bearer candidate into a byte-oriented comparison path so non-ASCII header material cannot escape the application-controlled authentication response as an uncaught type error. CWE 4.20 CWE-248 covers uncaught exceptions, and OWASP Top 10:2025 A10 addresses mishandling of exceptional conditions. Byte-oriented comparisons, explicit UTF-8 conversion, unrelated digest comparisons, and non-HMAC header checks remain outside this detector family.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
