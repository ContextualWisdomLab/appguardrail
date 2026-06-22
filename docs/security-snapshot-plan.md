# VibeSec Security Snapshot Plan

Date: 2026-06-22

## Goal

Turn `vibesec scan` from a pattern matcher into a local deploy-readiness snapshot for AI-built web apps.

## Observed Context

- The README promises a persistent security layer, monitor, fix guidance, and a "mini security team" experience.
- The methodology says VibeSec's real value is catching vibe-coded failures: IDOR, missing ownership checks, exposed service keys, permissive Supabase/Firebase rules, unsafe payments, and deferred auth TODOs.
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
- Defaults exclude docs, tests, examples, generated files, and VibeSec's own rule definitions from deploy-blocking counts.

## Product Decision

Do not add a sandbox scanner next. Sandbox scanning is only valuable after VibeSec defines a runnable app contract: start command, base URL, seeded test accounts, allowed routes, and destructive-action limits.

The next product primitive should be:

```bash
vibesec scan --trivy .
```

But its meaning should become "local security snapshot", not "regex scan plus Trivy output".

## Minimal Design

1. Discover context:
   - framework and package manifests
   - API routes and server actions
   - Supabase/Firebase/Stripe config files
   - docs/tests/examples/rule fixtures that should not count as deploy blockers

2. Run evidence sources:
   - VibeSec rule scan for vibe-coded app failures
   - Trivy FS when `--trivy` is enabled and installed

3. Normalize findings:
   - `source`: `vibesec-rule` or `trivy`
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
