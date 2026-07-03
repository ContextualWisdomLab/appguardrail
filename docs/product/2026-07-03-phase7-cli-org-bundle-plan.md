# AppGuardrail Phase 7 CLI Organization Bundle Plan

Date: 2026-07-03
Status: Active execution plan
Goal: make the buyer evidence bundle a first-class AppGuardrail CLI surface
instead of an internal CI script that beginners need to discover.

## Live Evidence Reviewed

- `ContextualWisdomLab/appguardrail` default branch is `develop`.
- Latest live `origin/develop` reviewed: `9bc82c4`.
- `ContextualWisdomLab` has 26 non-archived repositories: 20 non-forks, 6
  forks, and 3 private repositories.
- Primary-language distribution is Python 11, TypeScript 4, JavaScript 3, R 2,
  Shell 2, C++ 1, Java 1, Kotlin 1, and Rust 1.
- AppGuardrail has 6 open PRs; all are existing source-work or review-work
  gates unrelated to this phase.
- The org-level central required workflow ruleset is active, and repo rulesets
  `17073578` and `17214782` are active.
- CodeGraph is not initialized in this checkout, so this phase uses direct
  source reads and focused tests instead of CodeGraph queries.

## Plugin Perspectives Applied

### Superpowers

Use an isolated worktree from live `origin/develop`, keep a written plan,
verify with focused and full tests, then create, merge, and post-merge verify a
PR. Review waiting and queued checks are not blockers.

### Product Design

The command should read like a product action: `appguardrail org-bundle`.
Beginners should not have to know the internal script path or choose output
file names. The default bundle directory is stable and inspectable.

### Figma

No Code Connect. Update the existing FigJam board with the Phase 7 flow:
CLI command, live or JSON sources, shared core helper, and buyer artifacts.

### Data Analytics

The CLI output should expose the decision numbers that matter immediately:
open PRs analyzed, buyer evidence status, and collection warning count. The
manifest remains the auditable source for dashboards.

### Ponytail

Do not create a separate package, submodule, or service. The smallest correct
boundary is a shared `appguardrail_core.org_bundle` helper because the bundle
logic now has two real consumers: the product CLI and the CI report script.

## CLI Contract

`appguardrail org-bundle` writes `appguardrail-buyer-evidence/` by default:

- `org-readiness.md`: human-readable organization readiness report.
- `buyer-evidence.json`: machine-readable KPI payload.
- `manifest.json`: source, warning, artifact, repo, PR, action bucket, and KPI
  metadata.
- `README.md`: beginner-readable instructions for the bundle.

Automation can still pass `--bundle-dir`, `--owner`, `--repos-json`,
`--prs-json`, `--prs-repository`, `--per-repo-pr-limit`,
`--active-repository-target`, and `--generated-at`.

## Acceptance Criteria

- Focused tests cover the CLI command and the script compatibility path.
- Full pytest passes.
- `python3 -m py_compile` passes for changed Python modules.
- `git diff --check` passes.
- A live CLI bundle can render from current GitHub state.
- `python3 scanner/cli/appguardrail.py scan .` reports zero deploy-blocking
  critical/high issues.
- The Figma board is updated without Code Connect.
