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
| hostname-unbound loopback exception in a Python global-address validator | built-in `python-ssrf-allow-local-unbound-loopback` rule | active PR: exact EgressWeave vulnerable/fixed objects plus production scanner regression; bounded `_validate_global_address` source shape |
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

## EgressWeave local-loopback traceability contract

The source-backed local-development SSRF detector is distinct from both stored-webhook SSRF and generic workflow failure collection:

1. EgressWeave PR #1 source base is pinned to head `271a9bb95d2a6274065e3e5535afbb880dd27a55`, `src/egressweave/validation.py` blob `dc5bd8167593167a622de25d27e0f734b8d3eb5a`;
2. the vulnerable `_validate_global_address` source sets `is_allowed_local = True` when `policy.allow_local` and `ip_address.is_loopback` are true, without first binding the exception to the original hostname;
3. the reviewed fixed head is `81fc0a34cff7e8c90e3f0247342c0c8ee7de3d86`, blob `7295c7cbf17c5d2b06dd7f77430e6674d2f25320`, which checks the original local hostname before allowing its corresponding address classes;
4. an independent hostname-bound boolean variant and unrelated loopback-display logic are negative oracles;
5. production `_scan_file` must emit the normalized HIGH CWE-918 finding for the vulnerable replay and no finding for the reviewed fix;
6. repeated Strix collector events from the same EgressWeave PR may share this detector only because they refer to the same source change; generic OpenCode/Security Scan cancellation issues remain infrastructure provenance rather than SAST claims;
7. exact-head required checks and qualifying independent review are required before promotion to `implemented-main`.

The rule intentionally does not claim complete SSRF protection, RFC-range policy correctness, resolver pinning, redirect safety, proxy safety, socket/TLS identity binding, or connection-pool behavior.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
