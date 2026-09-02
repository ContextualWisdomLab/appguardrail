# Product / Technical Gap Baseline

**Status:** Active commercial-readiness baseline  
**Last reviewed:** 2026-09-03

This document records buyer-visible and control-plane gaps that are supported by current AppGuardrail code, tests, review evidence, and canonical-owner boundaries. It is not a substitute for live pull-request checks or protected-branch evidence.

## Product boundary

AppGuardrail owns reusable static-analysis and SARIF evidence. It may detect unsafe GitHub Actions control flow, but `.github` remains the canonical owner of organization-wide CI, review, runner, security, and release behavior. AppGuardrail must not copy or mutate that owner source to make a leaf detector pass.

The current GitHub Actions polling family covers a bounded conventional grammar: two-space Actions jobs, literal shell `run` blocks, executable `gh api` polling, transport-failure budgets, total deadline/attempt guards, selected state-reset patterns, and reviewed unreachable fail-closed exits. It does not claim general shell control-flow or data-flow analysis.

## Current implemented evidence

Issue #1087 is backed by the protected `.github` vulnerable predecessor `5c561a65cca3b925d533e4b40c5c3ac00f16524e` and protected wall-clock repair `e29302c05eade7da7b0bdbb453e53980bc9d577b`.

PR #1088 carries four HIGH/CWE-400 detector identities:

- `github-actions-transport-only-poll-bound` for the historical transport-budget incident shape;
- `github-actions-transport-failure-budget-poll-bound` for renamed failure-counter/limit shapes;
- `github-actions-poll-bound-state-reset` for reviewed non-convergent mutation of apparent total bounds;
- `github-actions-poll-bound-unreachable-exit` for reviewed guards whose fail-closed exit is unreachable.

The historical detector now requires causal transport-budget evidence rather than a matching setting name alone. Test-first commit `df4ff1c3f724764b1d047b2cb95ef491c096356c` pins both the negative unused-setting case and the positive counter-flow case. Production commit `a467678c7e3b4bedca8092eec28072fdd0aae90a` requires a zeroed counter, failing executable `gh api` path, counter increment, comparison with `max_poll_transport_failures`, and nonzero threshold exit in the same reviewed polling flow. Commit `5d87c36251391e5f0254eb915ca7f3068a22b21c` repairs older scope/timeout fixtures so positive historical tests use that same causal incident contract instead of relying on the configuration name alone.

## Commercial and technical gaps

| Gap | Current evidence | Acceptance |
|---|---|---|
| General GitHub Actions + shell control-flow analysis | The detector family deliberately uses bounded regex grammar and adjacency windows. Composite actions, generated workflows, non-shell control flow, cross-file state, noncanonical YAML structures, and materially different loop frameworks are explicit false-negative boundaries. | Introduce a structural Actions/shell analysis layer only with executable regression migration oracles, bounded performance evidence, and no regression in current detector identities. Do not claim universal shell semantics from more regex. |
| Exact-head security execution | PR #1088 has repeatedly produced CodeQL `startup_failure` runs with no materialized source job; the latest verified owner handoff for implementation head `a467678c7e3b4bedca8092eec28072fdd0aae90a` is CodeQL run `33681544597` with `jobs=[]`. | Canonical `.github` owner restores real job materialization/runner admission and the unchanged candidate obtains terminal source-analysis evidence. Startup failure, zero-job runs, predecessor success, or leaf no-op retriggers are not GREEN. |
| Protected integration | Production/test changes invalidate predecessor checks. AppGuardrail review threads remain evidence obligations until current-head tests and required controls are terminal GREEN. | Ordinary protected merge only after all live findings are reconciled, exact-head tests/security/SAST/code-scanning requirements pass, qualifying independent review is satisfied, and base ancestry remains valid. |
| Immutable release evidence | An active PR is not a released detector contract. | After protected integration, publish version/CHANGELOG/tag/package plus SBOM, provenance, reproducibility and rollback evidence through the repository's canonical release path before consumers treat this detector family as immutable release evidence. |

## Architecture decision

For #1087, retain the existing lightweight detector family as a bounded product capability and use its production `_scan_file` regressions as migration oracles. Do not expand regex until it can prove the next concrete buyer/security case without blocker-class false positives. If shell ownership, nested conditional pairing, composite-action flow, or cross-file state becomes material, move that responsibility into a structural Actions/shell analyzer with explicit AST/control-flow/data-flow semantics rather than accumulating regex that implies unsupported completeness.

The choice preserves the current low-cost scanner, keeps `.github` prevention authority separate from AppGuardrail detection authority, and makes the remaining coverage boundary visible to buyers and maintainers instead of hiding it behind broad security claims.

## Release gate

This baseline does not mark PR #1088 merge-ready or release-ready. Every source or documentation commit requires fresh exact-head verification. A current PR head, required checks, reviews, branch protection state, release state, and canonical-owner runner evidence must be read live before promotion.
