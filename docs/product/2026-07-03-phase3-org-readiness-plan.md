# AppGuardrail Phase 3 Org Readiness Plan

Date: 2026-07-03
Status: Active execution plan
Goal: make AppGuardrail credible as a 2B KRW sale-readiness product by turning
ContextualWisdomLab organization evidence into repeatable product inputs.

## Live Evidence Reviewed

- `ContextualWisdomLab/appguardrail` default branch is `develop`.
- `ContextualWisdomLab` had 26 non-archived repositories at the review point:
  20 non-forks and 6 forks.
- Primary-language distribution at the review point: Python 11, TypeScript 4,
  JavaScript 3, Shell 2, R 2, Rust 1, Java 1, C++ 1, Kotlin 1.
- GitHub search returned 200 open PRs before exhausting the requested page,
  which means the org has at least 200 open PRs needing classification.
- A later repo-by-repo detailed PR pass with a 30 PR per repository cap
  classified 309 open PRs: 109 source conflicts, 61 source review items,
  54 needs-triage items, 34 CI failures, 24 review-required items,
  21 external-queued gates, and 6 merge-ready PRs.
- `appguardrail` itself had 6 open PRs. PR #157 was conflicting and had
  current unresolved product-compatibility review comments, so it was not a
  review-process-only blocker.
- GitHub Actions required checks for recent `develop` and PR runs were queued,
  which is operational evidence but not a source-code blocker under the current
  execution policy.
- Product Design saved context was not configured, so current repo files,
  GitHub state, and generated Figma artifacts are the source of truth.
- Ponytail debt scan returned no `ponytail:` markers.

## Plugin Perspectives Applied

### Superpowers

Use a small branch per sale-readiness increment. Keep each increment backed by
a plan, tests, verification, PR, and explicit blocker classification.

### Product Design

The beginner-facing product cannot require a user to choose language profiles,
scanner engines, or workflow categories before first value. The useful first
screen is an operational posture surface: repo coverage, queued gates, source
work, CI failures, and report exports.

### Figma

Figma Code Connect remains out of scope. Use FigJam/Figma artifacts only to
explain the product loop and buyer demo flow: repos and PRs become normalized
org intelligence, org intelligence drives IssueOps and reports, and reports
support founder and buyer diligence conversations.

### Data Analytics

The KPI model should consume aggregate organization facts, not raw customer
code or full logs. The first measurable org facts are active repository count,
supported language coverage, PR gate split, CI failure routing, report exports,
and duplicate suppression.

### Ponytail

No local `ponytail:` debt markers were found in this worktree. Future shortcuts
must name a ceiling and upgrade trigger before merge.

## Library Split Decision

Do not introduce a submodule in Phase 3.

The repo already has `appguardrail_core`, and the next useful boundary is an
in-repo `org_intelligence` module. It can later become a separately versioned
package only after it has at least three stable consumers, such as CLI report
generation, scheduled GitHub workflow, hosted dashboard, and buyer diligence
export.

## Immediate Implementation Slice

1. Add `appguardrail_core.org_intelligence`.
2. Normalize GitHub repo JSON into an organization inventory.
3. Normalize open PR JSON into a gate summary that separates source conflicts,
   source review work, CI failures, queued checks, and review waiting.
4. Render a markdown org readiness report from the normalized model.
5. Add `scripts/ci/render_org_readiness_report.py` so live GitHub repository
   and PR state can be converted into a report artifact without sending raw
   code or logs outside GitHub.
6. Keep checks queued and review-process waiting as external gates, while
   keeping conflicts and actual change-requested PRs as product work.

## Acceptance Criteria

- Unit tests cover repository counting, language coverage, PR gate
  classification, and report recommendations.
- The report identifies unsupported language families that should start with
  external engines before built-in regex promotion.
- The implementation keeps `appguardrail_core` importable with no dependencies.
- `python3 -m py_compile`, focused pytest, full pytest, and `appguardrail scan .`
  pass on the branch.
- The Figma board is updated with the Phase 3 org intelligence flow and does
  not use Code Connect.
