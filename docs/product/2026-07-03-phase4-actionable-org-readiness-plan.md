# AppGuardrail Phase 4 Actionable Org Readiness Plan

Date: 2026-07-03
Status: Active execution plan
Goal: make the organization readiness report useful as a beginner-facing and
buyer-facing action surface, not only a count summary.

## Live Evidence Reviewed

- `ContextualWisdomLab/appguardrail` default branch is `develop`.
- Latest merged AppGuardrail commit reviewed: `4c8bea5`.
- `ContextualWisdomLab` currently has 26 non-archived repositories:
  20 non-forks and 6 forks.
- Primary-language distribution remains Python 11, TypeScript 4, JavaScript 3,
  Shell 2, R 2, Rust 1, Java 1, C++ 1, Kotlin 1.
- AppGuardrail currently has 6 open PRs, and all 6 are `CONFLICTING` /
  `DIRTY`. Those are product/source-work gates, not review-process-only gates.
- No `ponytail:` markers were found in the Phase 4 worktree.

## Plugin Perspectives Applied

### Superpowers

Keep this as a small, mergeable branch. The work should have a written plan,
focused tests, full validation, PR, merge, and ruleset restoration evidence.

### Product Design

The report should tell a beginner what to do first. A table of gate counts is
not enough. The useful surface is: action bucket, top repo by source work, and
first action wording that separates source work, CI failures, and external wait.

### Figma

No Code Connect. Update the FigJam product loop to show that PR gate data now
becomes action buckets and repo priorities before it becomes buyer evidence.

### Data Analytics

The key measurement improvement is to convert raw PR states into stable action
buckets: `source-work`, `ci-failure`, `external-wait`, `merge-ready`, and
`needs-triage`. These buckets are more useful than raw GitHub states because
they determine what a team should do next.

### Ponytail

No deliberate shortcut marker exists. Phase 4 should not add one; the intended
increment is small enough to finish without a deferral.

## Library Split Decision

Do not introduce a submodule or separate repository in Phase 4.

`appguardrail_core.org_intelligence` already has the right in-repo boundary.
The next step is to make that core model richer while keeping the CLI/report
script stable. A separate package should wait until there is a hosted service
or SDK consumer outside this repository.

## Immediate Implementation Slice

1. Add action buckets for PR gates.
2. Add top repository summaries by actionable work.
3. Add first-action recommendations to the markdown org readiness report.
4. Keep existing `summarize_pr_gates()` and report script behavior compatible.
5. Add focused tests for bucket mapping, top repo priority, and report copy.

## Acceptance Criteria

- Focused org-intelligence tests pass.
- Full pytest passes.
- `appguardrail scan .` has zero critical/high deploy blockers.
- A live org readiness report can still be rendered from GitHub repo JSON.
- Figma board is updated without Code Connect.
