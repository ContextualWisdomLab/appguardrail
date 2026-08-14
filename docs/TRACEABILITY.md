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
| Python Authorization Unicode strings passed directly to `hmac.compare_digest` | built-in `python-auth-header-compare-digest-unicode-string` rule | active PR: exact Newsdom vulnerable/protected-fixed blobs plus production scanner regression; bounded FastAPI source shape |
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

## Newsdom HMAC-header encoding traceability contract

The equivalent non-ASCII `Authorization` failure was observed in several generated Newsdom security PRs and collected as separate AppGuardrail workflow events. The detector family preserves those event identities while deriving efficacy from source, not from cancelled reviewer/scanner jobs:

1. vulnerable source is pinned to Newsdom API head `04491c0e9ac38b9f793029683cebfb8210ccfadd`, `src/newsdom_api/main.py` blob `4efdad56ed78ed5c0158cdf0d746aedfe72604fe`;
2. the vulnerable `require_authorization` path receives a FastAPI `Header()` string, assigns `provided = authorization or ""`, and passes `provided` directly to `hmac.compare_digest`;
3. Python's documented comparator contract restricts string operands to ASCII-only strings;
4. the protected fixed source is pinned to head `e06b1f3fb10903569124af011da213951e6e2473`, blob `f61aafc2d6592f4a84c7b02b50cfe4a972623463`, and uses a bounded byte-oriented Bearer parsing/comparison boundary;
5. independent negatives cover explicit UTF-8 conversion, direct ASCII rejection, the protected fixed source shape, and unrelated digest comparison;
6. production `_scan_file` must emit the normalized HIGH finding for the vulnerable replay and no finding for the tested remediation shapes;
7. the separate oversized-header resource limit from Newsdom PR #497 is intentionally not promoted by this detector and remains a separate obligation if retained;
8. only exact-head required checks and qualifying independent review may promote this family to `implemented-main`.

Collector issues for Newsdom PRs #487, #489, #493, #495, and #499 may be consolidated by one merged detector PR only because their core source weakness is the same direct Unicode-string comparison boundary. Workflow outcome alone is never sufficient for consolidation or closure.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
