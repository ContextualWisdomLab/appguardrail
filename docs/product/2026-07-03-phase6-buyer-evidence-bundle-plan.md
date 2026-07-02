# AppGuardrail Phase 6 Buyer Evidence Bundle Plan

Date: 2026-07-03
Status: Active execution plan
Goal: package the organization readiness report into a one-command buyer
evidence bundle that a beginner can generate without choosing output files,
scanner families, or GitHub gate terminology.

## Live Evidence Reviewed

- `ContextualWisdomLab/appguardrail` default branch is `develop`.
- Latest live `origin/develop` reviewed: `c6399f43`.
- `ContextualWisdomLab` has 26 non-archived repositories: 20 non-forks, 6
  forks, and 3 private repositories.
- Primary-language distribution is Python 11, TypeScript 4, JavaScript 3, R 2,
  Shell 2, C++ 1, Java 1, Kotlin 1, and Rust 1.
- AppGuardrail has 6 open PRs; all remain source-work gates rather than
  review-process-only blockers.
- The org-level central required workflow ruleset is active.
- CodeGraph is not initialized in this checkout, so this phase uses direct
  source reads and focused tests instead of CodeGraph queries.

## Plugin Perspectives Applied

### Superpowers

Keep this as one isolated branch with a written plan, focused test coverage,
full verification, PR, merge, and ruleset restoration evidence. Review waiting
and queued checks are tracked but are not blockers.

### Product Design

The beginner-facing surface is the bundle directory, not a matrix of flags.
Each file has a clear job: narrative, machine-readable evidence, manifest, and
operator README. The manifest makes the evidence auditable without asking the
user to understand raw GitHub API fields.

### Figma

No Code Connect. Update the existing FigJam board with the Phase 6 evidence
bundle flow: live GitHub state, readiness summarization, bundle artifacts, and
buyer data-room use.

### Data Analytics

Treat the bundle as a decision artifact. The manifest must include the source,
generated time, repo and PR counts, action buckets, and overall KPI status so a
buyer or dashboard can validate the snapshot without parsing Markdown.

### Ponytail

Do not split a separate library or add a submodule in this phase. The existing
`appguardrail_core.org_intelligence` contract and one CLI script are enough.
Split only after a hosted service, SDK, or independent third-party consumer
needs versioned access.

## Bundle Contract

`scripts/ci/render_org_readiness_report.py --bundle-dir <dir>` writes:

- `org-readiness.md`: human-readable organization readiness report.
- `buyer-evidence.json`: machine-readable KPI payload.
- `manifest.json`: generated timestamp, data sources, repo-level collection
  warnings, artifact names, repo and PR counts, action buckets, and buyer
  evidence status.
- `README.md`: beginner-readable instructions for using the bundle.

The existing `--out` and `--json-out` flags remain supported for automation
that already knows exactly which single file it wants.

## Acceptance Criteria

- Focused tests cover bundle file creation and manifest summary fields.
- Full pytest passes.
- `python3 -m py_compile` passes for changed Python modules.
- `git diff --check` passes.
- A live org bundle can render from current GitHub state, preserving repo-level
  GitHub API failures as manifest warnings instead of dropping them silently.
- `python3 scanner/cli/appguardrail.py scan .` reports zero deploy-blocking
  critical/high issues.
- The Figma board is updated without Code Connect.
