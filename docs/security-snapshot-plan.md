# AppGuardrail Security Snapshot Plan

Date: 2026-06-22

## Goal

Turn `appguardrail scan` from a pattern matcher into a local deploy-readiness snapshot for AI-built web apps.

## Observed Context

- The README promises a persistent security layer, monitor, fix guidance, and a "mini security team" experience.
- The methodology says AppGuardrail's real value is catching AI-coded failures: IDOR, missing ownership checks, exposed service keys, permissive Supabase/Firebase rules, unsafe payments, and deferred auth TODOs.
- GitHub issues are empty, and the open PR queue is mostly scanner performance, false-positive UX, and CI hardening work.
- The current scanner can find risky text, but it also flags its own rules, tests, docs, and vulnerable examples. That is not enough for a deploy decision.
- Trivy FS is useful, but only as one evidence source. It does not answer whether a Next.js/Supabase app enforces ownership or whether a Stripe flow is safe.

## User Stories

### US1: Solo Builder Deploy Gate

As a founder building with Cursor, Claude Code, Lovable, Replit, or Bolt, I want one local command before deploy so I know whether I can ship or must fix security blockers.

Acceptance:
- The command runs offline against a local repo by default.
- It separates deploy blockers from examples, tests, docs, and scanner rule fixtures.
- It explains each blocker as problem, risk, fix prompt, and verification.
- It exits non-zero when critical or high deploy blockers are found.

### US2: AI-Assisted Fix Loop

As a developer using an AI coding assistant, I want each finding to include a precise fix prompt and verification step so I can remediate without translating scanner jargon.

Acceptance:
- Every promoted finding includes affected file, line, category, severity, and fix prompt.
- Verification is concrete: test to add, request to make, or config check to run.
- Secret findings never print the secret value.

### US3: Authorized Reviewer Snapshot

As an agency, consultant, or internal reviewer, I want a scope-aware local report so I can review only code I am authorized to assess.

Acceptance:
- The tool stays local by default and does not attack live services.
- Output records scanned path, excluded paths, enabled engines, and timestamp.
- The report is suitable to share privately with the app owner.

### US4: CI Regression Guard

As a maintainer, I want CI to catch new security regressions without breaking builds on educational samples or scanner fixtures.

Acceptance:
- Machine-readable JSON is available for CI.
- Findings have `source`, `category`, `confidence`, and `context` fields.
- Defaults exclude docs, tests, examples, generated files, and AppGuardrail's own rule definitions from deploy-blocking counts.

## Product Decision

Do not add a sandbox scanner next. Sandbox scanning is only valuable after AppGuardrail defines a runnable app contract: start command, base URL, seeded test accounts, allowed routes, and destructive-action limits.

The next product primitive should be:

```bash
appguardrail scan --trivy .
```

But its meaning should become "local security snapshot", not "regex scan plus Trivy output".

## Minimal Design

1. Discover context:
   - framework and package manifests
   - API routes and server actions
   - Supabase/Firebase/Stripe config files
   - docs/tests/examples/rule fixtures that should not count as deploy blockers

2. Run evidence sources:
   - AppGuardrail rule scan for AI-coded app failures
   - Trivy FS when `--trivy` is enabled and installed

3. Normalize findings:
   - `source`: `appguardrail-rule` or `trivy`
   - `category`: `authz`, `secrets`, `payment`, `storage`, `dependency`, `injection`, `misconfig`
   - `confidence`: `high`, `medium`, `low`
   - `context`: `app-code`, `test`, `doc`, `example`, `scanner-fixture`
   - `fix_prompt`
   - `verification`

4. Triage:
   - only `app-code` findings can block deploy by default
   - docs, tests, examples, and scanner fixtures remain visible but non-blocking
   - critical/high app-code findings keep the current non-zero exit behavior

5. Report:
   - keep the terminal summary short
   - add JSON output before adding HTML or dashboards

## Implementation Order

1. Done: add context classification for file paths.
2. Done: extend finding objects with `source`, `category`, `confidence`, `context`, `fix_prompt`, and `verification`.
3. Done: fold Trivy findings into the same normalized object shape.
4. Done: change deploy-blocking counts to ignore non-app contexts by default.
5. Deferred: add `--json <path>` only after the normalized object shape is stable.

Skipped for now: sandbox scanning, HTML reports, cloud upload, custom CVE database, and live endpoint probing. Add them only after the local snapshot produces trustworthy deploy decisions.

## Product Reframe: 2026-06-23

AppGuardrail should become the smallest useful security operating loop for AI-built apps, not another scanner catalog. The product has to answer one question for a builder or reviewer: "Can this change ship, and what exact fix should I ask my AI coding tool to make if it cannot?"

### Current Signals

- The CLI now has a local deploy gate and Trivy-backed evidence, but the README still needs stronger trust signals for contributors.
- The repository now has AI-assisted review and Strix security workflows, so the missing layer is a cheap baseline process that always runs without model credentials.
- Existing findings show why context classification matters: docs, tests, examples, and scanner fixtures can contain intentionally vulnerable text and should stay visible without blocking deploys.
- Sandbox scanning remains premature until the product has a runnable app contract.

### Revised User Stories

#### US5: Contributor Trust Signal

As a contributor, I want one README badge path to the project knowledge base and one visible security-process badge so I can understand the project and see whether baseline security checks are healthy.

Acceptance:
- README links to DeepWiki for repository understanding.
- README links to the baseline security workflow result.
- The badge target is the canonical `ContextualWisdomLab/appguardrail` repository.

#### US6: Baseline Security Process

As a maintainer, I want a security workflow that does not depend on LLM credentials so every PR and protected-branch push gets a deterministic baseline check.

Acceptance:
- The workflow runs `appguardrail scan .`.
- The workflow runs Trivy FS for critical/high vulnerabilities, secrets, and misconfigurations.
- Trivy SARIF is uploaded to code scanning when GitHub permissions allow it.
- Scan outputs are retained briefly as artifacts for review.

#### US7: Product Learning Loop

As the product owner, I want each security-process failure to teach the next product primitive instead of becoming a one-off CI fix.

Acceptance:
- Failures are classified as local rule, Trivy evidence, Strix/AI evidence, or workflow infrastructure.
- The next feature is chosen only after a failure repeats or blocks a real deploy decision.
- Sandbox scanning waits for a documented runtime contract.

### Product Decision

Add a baseline `Security Process` workflow now. Keep Strix and OpenCode as higher-signal review layers, but do not make them the only security process because they can depend on model availability, credentials, and longer review cycles.

Do not build a dashboard, sandbox runner, or new report format in this step. The next code feature should still be JSON output for `appguardrail scan` because CI and product learning both need a stable machine-readable artifact.
