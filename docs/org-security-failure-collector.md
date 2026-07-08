# Org Security Failure Collector

`.github/workflows/org-security-failure-collector.yml` +
`scripts/ci/collect_org_security_failures.py` +
`appguardrail_core/issueops.py`.

A scheduled (every 30 min) org-wide collector that walks completed GitHub
Actions workflow runs across `ContextualWisdomLab`, finds **failing**
security/CI workflows (name matches `strix` / `opencode` / `appguardrail` /
`trivy` / `codeql` / `security process`), redacts the failing job log, and
maintains **one issue per `repo:workflow`** in
`ContextualWisdomLab/appguardrail`.

## Why this exists alongside the Strix emitter

There are two independent issue producers. They are deliberately scoped so they
never file the same issue:

| Producer | Trigger | Granularity | Labels |
| --- | --- | --- | --- |
| **This collector** (`appguardrail`) | A security/CI **workflow run failed** (e.g. the contextual-orchestrator Strix run that died on a GitHub Models `RateLimitError` — an *infra* failure, not a vuln) | one issue per `repo:workflow` | `org-security-failure`, `security-ci`, **`ci-failure`**, `repo:<name>` |
| **Strix emitter** (central `.github`, sibling PR #358) | A Strix scan produced a **vulnerability finding** | one issue per *finding* | `strix`, `security` |

The `ci-failure` label is the durable marker of the split: infra/workflow
failures here, per-finding vulns there.

## Authentication

The collector authenticates with the **existing OpenCode GitHub App** via the
OIDC token exchange (`POST https://api.opencode.ai/exchange_github_app_token`),
mirroring the central Strix workflow. It requires `id-token: write` and no
bespoke, per-collector App. When the exchange is unavailable, the job falls
back to `GITHUB_TOKEN` and forces **DRY-RUN** (logs intended writes, mutates
nothing, exits 0) — so it is always best-effort and never fails the schedule.

## Behavior

- **Dedup** on a stable key: `sha256(repo + workflow + normalized failure
  signature)` (run/job ids and other volatile numbers normalized out). A
  recurring failure **updates** its issue instead of spamming a new comment
  each run.
- **Close-on-fix**: when a security workflow's most recent completed run
  **succeeds**, the corresponding open issue is closed with a resolved comment
  (reopens if it fails again).
- **Redaction**: ANSI, timestamps, and secret shapes (bearer tokens,
  `gh*_`/`github_pat_`/`sk-` tokens, JWTs) are stripped from embedded logs.

## Manual step (one-time)

Grant the **existing OpenCode GitHub App** `Issues: Read and write` on
`ContextualWisdomLab/appguardrail` (it already has the cross-repo `Actions` /
`Checks` read access the Strix workflow uses). No new App, App ID, or private
key is provisioned. Until then the collector simply runs in DRY-RUN.
