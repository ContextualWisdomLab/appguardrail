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
| automatic scanner detection of Wardnet-style Rust auth secrets sourced directly from process env | built-in `rust-auth-secret-raw-env-runtime-source` rule | active-PR; source-authoritative Wardnet vulnerable/fixed replay on `feat/rust-auth-secret-env-source-detector` |
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

## Wardnet administrator-secret source family

Collector issues #449, #450, and #451 record cancelled security/review jobs for Wardnet PR #55 and are provenance only. The executable SAST obligation is established independently by the reviewed source delta:

- vulnerable source repository: `ContextualWisdomLab/wardnet`;
- vulnerable revision: `867d3186652bca1277aa9f08b2d312bbd71e0beb`;
- vulnerable `src/lib.rs` blob: `15ac355b052a38daac13c36ad0a5fbac5443249e`;
- reviewed fixed PR #55 head: `ab294c4cb2cc25f2369cf203dc81a65ec071dda7`;
- fixed `src/lib.rs` blob: `fce07f799369607771ad6f5b474c94d7df9bb708`.

The vulnerable source passes `std::env::var("ADMIN_TOKEN")` directly into `AppConfig.admin_token` and reads `ADMIN_TOKENS` directly at `parse_admin_tokens(...)`. The reviewed repair makes environment/file inputs bootstrap transports into `CredentialRegistry`, then makes runtime auth consume `get_credential(...)`. Positive and negative fixtures preserve that distinction; ordinary non-secret operational environment reads and registry-bootstrap-only reads are negative oracles.

Rule `rust-auth-secret-raw-env-runtime-source` is deliberately source-specific rather than a blanket environment-variable prohibition. It uses Rust syntax plus `std::env::var`, `ADMIN_TOKEN`, and `admin_token` prefilters, emits CWE-526 evidence, and is exercised through production `_scan_file` on a `.rs` fixture. It does not claim general Rust taint analysis or first-class Rust language-profile support.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.