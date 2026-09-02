# AppGuardrail Requirements, Detection, and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-09-02

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
| tenant-scoped Spring admin authorization context continuity | built-in `java-spring-admin-discarded-tenant-context` rule + source-backed fixture replay | PR #963 active-PR; issue #550 is collector provenance only; exact vulnerable/fixed source blobs pinned |
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

## Tenant authorization traceability contract

PR #963 traces AppGuardrail issue #550 separately from source proof. The collector event points to Clearfolio PR #240 at `0eb7fa9cfc56062983f5337228ca3a7317cf17a8`; the positive source fixture is exact Git blob `5086b1d3797a9c32831900d09d93d8df44c5e13a`. Clearfolio PR #240 names #172 as superseding; the reviewed negative oracle is `f4ae8dd695afe1dd41decbc7e6b2a11d0ee5e461`, exact Git blob `872f0a66ea6dc8da95f8327e3d4cf40d3c08689f`, and remains unmerged. Promotion therefore requires AppGuardrail PR #963 source/tests to merge under fresh protected-head evidence; neither the failed collector workflow nor the unmerged Clearfolio fixed candidate can independently promote detector maturity.

As of 2026-09-02, Clearfolio PR #541 at exact head `1337efe45640740b338d021d64e41c045ecf7201` is the live causal-owner repair candidate for this authorization boundary. It requires `JOB_READ`/`JOB_DELETE`/`JOB_RETRY`, moves tenant scoping into application/persistence contracts, collapses missing and cross-tenant resources to the same 404 behavior, and separates retry audit pseudonymization from authorization through a keyed/domain-separated HMAC port. A concurrent descendant `020c0ec0337dce38cca4b7e653c5fb47fe6233c4` had reintroduced controller-local/global tenant filtering plus keyless SHA-256 and deleted the stronger application-port/HMAC regression corpus; `1337efe...` repairs that branch regression non-destructively by restoring the complete validated predecessor tree while retaining `020c0ec...` in history. Because #541 remains open and the new exact-head checks are non-terminal, it is causal provenance only and does not replace the pinned #172 negative oracle or promote detector maturity. If #541 merges, refresh the fixed-source oracle from the protected Clearfolio head rather than silently treating this open candidate as shipped truth.

The executable evidence path is `scanner/rules/java_tenant_authorization.yml` plus `tests/test_java_spring_tenant_authz_scope_rules.py`, `tests/test_java_spring_tenant_authz_source_fixtures.py`, and `tests/test_java_spring_tenant_authz_fixture_scan.py`; detector doctoring and bounded remediation guidance live in `docs/detectors/java-spring-tenant-authorization-scope.md`.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
