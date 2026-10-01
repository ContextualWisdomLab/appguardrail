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
| SCIM full replacement without a merged-account tombstone guard | built-in `python-scim-put-tombstone-resurrection` rule | active PR: exact Keyverse vulnerable/protected-fixed blobs plus source-derived negatives and production scanner replay |
| dynamic Keyverse healthcheck URL without an HTTP(S) protocol boundary | built-in `python-healthcheck-unrestricted-url-scheme` rule | active PR: MEDIUM defense-in-depth source slice; exact vulnerable/protected-fixed blobs and production scanner replay |
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

## Keyverse PR #32 traceability contract

The Keyverse source PR contains two distinct SAST-capable hardening families. Cancelled Strix/OpenCode runs are retained as provenance only; source changes and current protected-main negatives establish the detector obligations.

### SCIM tombstone replacement

1. vulnerable Keyverse base head is `938530663fc9c4129fd309f81f8f44b147728b1e`, `services/account_unification/app/scim.py` blob `2cb7609c1bd934670cba1a513f64908f8225601f`;
2. the vulnerable SCIM PUT handler checks existence, converts the incoming User resource, and calls `provisioner.replace_user` without enforcing the product's merged-account tombstone invariant;
3. protected fixed source is pinned to main head `ce207dfd42975db61c82a5963e206fc1db14ac2b`, blob `4c0b9fbca9d54a9c2237baf3879512ba17a4295d`, and checks `TOMBSTONE_ATTRIBUTE_KEY` while holding the same user-operation lock used by merge operations;
4. an independently authored explicit `merged_into_user_id` guard is a negative oracle;
5. production `_scan_file` must emit the normalized HIGH CWE-841 finding on the vulnerable replay and no finding on the reviewed repair.

### Dynamic healthcheck URL scheme

1. vulnerable healthcheck blob is `4284510ce94ac7148aeaec860b69b65d538b4acb` on the same base head and passes configurable `url` directly to `urllib.request.urlopen`;
2. protected fixed blob is `fd33ac621a2c7c86553ee3049e98d7ac91189186` on current main and limits the initial scheme to HTTP(S), uses an HTTP(S)-only `OpenerDirector`, and rejects non-HTTP(S) redirects;
3. an independently authored initial `urlsplit` allow-list and a literal local self-probe are negative oracles;
4. production `_scan_file` must emit a normalized MEDIUM CWE-918 finding on the vulnerable replay and none on the reviewed repair;
5. the detector is explicitly defense-in-depth because the Keyverse source change describes the container health URL as not attacker-controlled; a remote SSRF claim requires separate input-provenance evidence.

Repeated Strix collector issues #576, #577, #823, #824, #826, #832, and #838 may share this merged detector PR because they all belong to Keyverse PR #32, whose source change contains these two independently tested security families. Generic Required OpenCode Review cancellation issues #822, #825, #827, #833, and #839 remain infrastructure/reviewer provenance and are excluded from detector closure.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
