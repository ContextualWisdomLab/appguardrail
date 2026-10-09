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
| broad every-issue executable obligation coverage | issue-detection audit | not implemented; historical PR #911 closed as an inventory prototype |
| source-authoritative GitHub Actions run/job evidence | `appguardrail_core.github_actions_evidence`, CLI, exact coverage/mutation workflow | PR #939 active-PR; bounded vertical slice |
| authenticated workflow-result source identity | fixed GitHub REST origin, exact run/job/repository/SHA/freshness/digest validation | PR #939 active-PR |
| automatic scanner detection of unsafe stored-webhook SSRF pattern | built-in `python-stored-ssrf-webhook-url` rule | implemented-main through PR #910 for tested Python `set_webhook` direct and one-hop persistence flows; bounded scope |
| structural Semgrep-style `pattern:` execution by lightweight engine | built-in scanner | not implemented unless a real structural matcher is added; fixtures are not execution |

## Promotion rules

- `implemented-main` requires source/tests on protected `develop`, not an issue/PR description.
- `active-PR` becomes current only after merge plus fresh protected-head required evidence.
- External-engine capability must name the engine and availability; normalization does not convert it into a built-in detector.
- A prevention/hardening change does not automatically promote the matching scanner-detection row; PR #924 and PR #910 were verified and promoted independently.
- An issue registry mapping cannot promote an obligation unless actual detector execution derives its result from independent/closed evidence.
- A source-evidence acquirer does not promote the scientific or operational efficacy of the underlying workflow detector; that detector still needs its own independent oracle.

## Issue #938 / PR #939 traceability contract

| Requirement | Production path | Exact verification |
|---|---|---|
| no caller Boolean as truth | `acquire_actions_job` fetches run and job before `verify_actions_job` | exact endpoint and fake-client tests |
| explicit probe/acquirer identity | `PROBE_REF`, `ACQUIRER_REF` | evidence envelope assertions |
| exact source identity | repository, run/job IDs and URLs, run-on-job ID, head SHA | mismatch matrix and acquisition identity tests |
| bounded trusted transport | `GitHubApiClient` | origin/path/redirect/content-type/size/timeout/network tests |
| terminal security outcome | completed run/job/steps and security-name taxonomy | pass/failure/cancelled/non-security/unfinished tests |
| temporal and replay safety | `observed_at`, positive bounded `max_age`, digest ledger | future/stale/non-finite/excessive/duplicate tests |
| deterministic source identity | canonical bounded JSON projection + SHA-256 | mapping-order stability and duplicate tests |
| token/raw-log exclusion | header-only token and bounded projection | token non-disclosure and sanitized-error tests |
| production interface | console script and `main` | pass `0`, failure `1`, inconclusive `2` tests |
| predicate robustness | isolated source mutation execution | identity, obligation, outcome, acquisition mutation oracles |
| quality contract | dedicated exact-head workflow | 100% statements, 100% branches, complete docstrings |
| architecture/operations | ADR-0007, `ARCHITECTURE.md`, source-evidence runbook | documentation review |

Historical issue #815 supplies a reproducible GitHub Actions failure shape, but the expected outcome remains independently asserted in tests. PR #939 intentionally does not import the 20k-line PR #911 registry or present self-derived registry fixtures as independent evidence.

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

## Standards/research

The GitHub Actions evidence slice applies GitHub's versioned REST Actions job contract, NIST SP 800-53 Rev. 5 Release 5.2.0 audit/assessment/access/supply-chain control families, NIST SP 800-218 SSDF 1.1, SLSA 1.2 provenance concepts, and RFC 8259 JSON constraints. APA 7th entries and decision mapping are recorded in ADR-0007 and `docs/github-actions-source-evidence.md`.

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector, evidence acquirer, or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.