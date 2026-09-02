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
| GitHub Actions transport-only polling bound | built-in `github-actions-transport-only-poll-bound` plus identifier-agnostic causal companion `github-actions-transport-failure-budget-poll-bound` | Issue #1087 / active PR; verified causal owner repair is protected `ContextualWisdomLab/.github@e29302c05eade7da7b0bdbb453e53980bc9d577b` |
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

## GitHub Actions polling-bound traceability contract

Issue #1087 records a verified control-plane availability defect from `ContextualWisdomLab/.github`. At vulnerable protected predecessor `5c561a65cca3b925d533e4b40c5c3ac00f16524e`, the required OpenCode verdict step used a transport-failure counter around `gh api` calls but had no total bound for the path where every API call succeeded and no verdict appeared. Protected repair `e29302c05eade7da7b0bdbb453e53980bc9d577b` adds a 10,800-second wall-clock deadline checked on every loop iteration and fails closed when it expires.

The AppGuardrail obligation is the reusable causal pattern, not the workflow, issue title, or the historical shell identifier spelling. `github-actions-transport-only-poll-bound` preserves the pinned source incident and its reviewed job/run/loop boundaries while only treating a deadline/attempt guard as safe when the exact compared state is initialized before that same loop and the guard fails closed there. `github-actions-transport-failure-budget-poll-bound` closes the identifier-renaming false-negative boundary with a stricter causal proof: it captures arbitrary shell identifiers only when a zeroed failure counter is incremented on the failing `gh api` branch, compared against a positive retry limit, and causes a nonzero exit at the threshold while the healthy-transport/no-result path can still sleep and repeat. The companion excludes the historical `max_poll_transport_failures` form so one incident is not emitted twice.

Both rules are deliberately bounded to conventional two-space GitHub Actions job syntax and literal block shell steps. Evidence split across jobs, across run steps, or after the loop is negative; quoted `gh api`/`sleep` strings and shell comments are not executable evidence. Safety evidence is local to the same candidate job and loop: an explicit timeout on that job is a bound, and a loop deadline/attempt guard is a bound only when its state is initialized before the loop and the same state is consumed by an in-loop nonzero-exit guard. Uninitialized variables and state first assigned after its guard remain positive. A bounded helper loop cannot donate deadline/attempt evidence to a later vulnerable poll. Conversely, when the healthy API path unconditionally `break`s or `exit 0`s before the direct sleep/back edge, the loop is finite and must not produce this HIGH finding. A comparison that only logs without terminating is not a safety guard, and unrelated numeric variables are not a transport-failure budget unless the failure branch links the counter, limit, increment, threshold, and nonzero exit.

Regression evidence lives in `tests/test_github_actions_poll_bounds.py`, `tests/test_github_actions_poll_bound_aliases.py`, `tests/test_github_actions_poll_bound_late_initialization.py`, `tests/test_github_actions_poll_bound_review_20260902.py`, and the pinned answer-free source fixtures under `tests/fixtures/security_corpus/github_actions_transport_only_poll_{vulnerable,fixed}.yml`. The current-review regressions specifically preserve historical uninitialized/late deadline and attempt-state positives, earlier bounded deadline/attempt helper-loop positives for a later renamed vulnerable poll, and finite successful-path `break`/`exit 0` negatives. Current false-negative boundaries include cross-file/composite-action polling, non-shell control flow, dynamically generated workflows, quoted/nonstandard job-key syntax, noncanonical YAML indentation, retry-counter/limit declarations or multiple-helper arrangements outside the reviewed companion grammar, shell loops whose structure differs materially from the reviewed `while ... done` form, and unrelated retry frameworks. These remain explicit obligations rather than implied coverage. The detector family remains active-PR evidence until its exact head passes required checks and ordinary protected integration; the already-protected `.github` repair is prevention/control-plane evidence only and does not itself satisfy AppGuardrail scanner coverage.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
