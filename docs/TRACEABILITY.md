# AppGuardrail Requirements, Detection, and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-08-12

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
| automatic detection of unauthenticated urllib DNS validation-to-connect races | built-in `python-unauthenticated-urllib-dns-validation-to-connect` rule and `docs/detectors/ssrf-dns-validation-to-connect.md` | PR #1327 active-PR; Issue #1267 vulnerable/fixed corpus with bounded direct, `urlopen`, and redirect-handler flows |
| automatic detection of Python DNS-resolution fail-open URL validators | built-in `python-ssrf-dns-resolution-fail-open` rule and `docs/detectors/ssrf-dns-resolution-fail-open.md` | PR #1327 active-PR; Issue #1267 exact `gethostbyname`/`getaddrinfo` vulnerable lineage, fail-closed negatives, and fixed pinned-validation oracle |
| automatic detection of hostname-unbound local-address exceptions | built-in `python-ssrf-hostname-unbound-local-address-exception` rule and `docs/detectors/ssrf-hostname-unbound-local-exception.md` | PR #1327 active-PR; Issue #850 exact EgressWeave vulnerable/fixed heads, hostname-bound negatives, and immutable owner-release gap |
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

Current protected-branch evidence keeps those controls distinct: PR #924 supplies the fail-closed webhook storage boundary, and PR #910 supplies the packaged `python-stored-ssrf-webhook-url` detector plus focused regression corpus. PR #1327 proposes the separate execution-time pinned transport, two Issue #1267 detector families, and Issue #850's bounded hostname-unbound local-address-exception detector. The Issue #850 corpus pins EgressWeave vulnerable head `2d9dc094409bdc3574bcee6b9a5c52ea920b3936` / blob `caea83981a50407528ce3d45d16a5643d5ef0fbf` and fixed head `81fc0a34cff7e8c90e3f0247342c0c8ee7de3d86` / blob `7295c7cbf17c5d2b06dd7f77430e6674d2f25320`; owner merge `6f337b67efd985bdfcb16646fa3726709bd2e17e` is not an immutable release. The TOCTOU detector excludes Bearer-authenticated flows owned by PR #1080 and does not replace PR #944's detector for missing redirect revalidation. The fail-open and local-exception detectors do not join aliases, wrappers, dictionary-based policy access, cross-function decisions, or alternative admission shapes. None of these controls expands beyond its declared source/sink and flow contract.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
