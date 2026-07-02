# AppGuardrail Phase 5 Buyer Evidence Pack Plan

Date: 2026-07-03
Status: Active execution plan
Goal: make organization readiness output useful as buyer due-diligence evidence
that a beginner can generate without choosing languages, tools, or workflow
categories.

## Live Evidence Reviewed

- `ContextualWisdomLab/appguardrail` default branch is `develop`.
- Latest live `origin/develop` reviewed: `9aecc290`.
- `ContextualWisdomLab` has 26 non-archived repositories: 20 non-forks, 6
  forks, and 3 private repositories.
- Primary-language distribution is Python 11, TypeScript 4, JavaScript 3, R 2,
  Shell 2, C++ 1, Java 1, Kotlin 1, Rust 1.
- AppGuardrail has 6 open PRs; all remain source-work gates rather than
  review-process-only blockers.
- A live repo-by-repo PR pass with a 30 PR cap analyzed 308 open PRs:
  171 source-work, 51 needs-triage, 45 external-wait, 35 CI-failure, and
  6 merge-ready items.
- Top source-work repositories are `ContextualWisdomLab/codec-carver`,
  `ContextualWisdomLab/.github`, `ContextualWisdomLab/pg-erd-cloud`,
  `ContextualWisdomLab/fast-mlsirm`, and
  `ContextualWisdomLab/ContextualWisdomLab.github.io`.
- CodeGraph is not initialized in this checkout, so Phase 5 uses direct source
  reads and focused tests instead of CodeGraph queries.

## Plugin Perspectives Applied

### Superpowers

Keep this as one mergeable branch with a written plan, focused tests, full
verification, PR, merge, and ruleset restoration evidence.

### Product Design

The output should work as a first-run beginner surface: status, observed value,
target, and next action. A buyer should not need to interpret raw GitHub states
or know which scanner to run first.

### Figma

No Code Connect. Update the existing FigJam board with the Phase 5 flow:
org facts become PR gates, action buckets, KPI checks, a 7-day plan, and a
buyer evidence packet.

### Data Analytics

Treat the report as a decision artifact. The relevant KPIs are active repo
coverage, supported language coverage, source-work burden, CI-failure burden,
and reusable evidence export availability. Each must show pass, warn, or fail.

### Ponytail

Do not split a package or add a submodule yet. The lazy boundary is the existing
`appguardrail_core.org_intelligence` module plus one JSON export flag. Split
only after there are multiple external consumers.

## Library Split Decision

Do not create a separate library or submodule in Phase 5.

The reusable boundary already exists inside `appguardrail_core`. A separate
package would add release and compatibility work before there is a hosted
service, SDK, or third-party integration consuming it independently.

## Immediate Implementation Slice

1. Add a buyer evidence pack model to `appguardrail_core.org_intelligence`.
2. Compute pass/warn/fail KPI rows from existing inventory and PR summaries.
3. Add a 7-day execution plan generated from the same facts.
4. Append the evidence pack to the Markdown organization readiness report.
5. Add `--json-out` to the report script so dashboards or buyer packets can
   reuse the same evidence without parsing Markdown.

## Acceptance Criteria

- Focused tests cover KPI status, JSON shape, Markdown output, and 7-day plan.
- Full pytest passes.
- `python3 -m py_compile` passes for changed Python modules.
- `git diff --check` passes.
- `python3 scanner/cli/appguardrail.py scan .` reports zero deploy-blocking
  critical/high issues.
- A live org report can render both Markdown and JSON from GitHub state.
- The Figma board is updated without Code Connect.
