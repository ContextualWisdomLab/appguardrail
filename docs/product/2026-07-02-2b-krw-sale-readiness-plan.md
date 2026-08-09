# AppGuardrail 2B KRW Sale Readiness Plan

Date: 2026-07-02
Status: Active execution plan
Audience: founders, maintainers, pilot buyers, acquisition diligence reviewers

## Goal

Raise AppGuardrail from an alpha CLI and rule pack into a product that can be
credibly discussed as a 2B KRW acquisition target. The target is not a valuation
claim. It is an execution standard: the repository must show productized IP,
repeatable buyer value, beginner-safe onboarding, measurable risk reduction,
and a credible path from open-source trust to paid deployment.

Operational constraints:

- Figma Code Connect is out of scope.
- Beginner users must not need to choose languages, scanners, or security
  frameworks before the first useful result.
- Review waiting is not a delivery blocker; technical failures, permissions,
  and external service outages are blockers.
- Customer code and logs must be treated as sensitive. Product analytics must
  work from metadata and redacted finding summaries.

## Market And Product Signals

AppGuardrail should position itself between classic SAST tools and application
security posture management:

- GitHub Code Security is listed at 30 USD per active committer per month, and
  GitHub Secret Protection at 19 USD per active committer per month. AppGuardrail
  should not compete as another per-seat scanner only; it should compete on
  zero-configuration guidance, AI-builder workflows, and issue operations.
  Source: https://github.com/security/plans
- Snyk's public plan page emphasizes developer-first scanning, SAST, SCA,
  container, IaC, prioritization, and reporting. AppGuardrail should integrate
  complementary engines rather than replace all of them. Source:
  https://snyk.io/plans/
- Gartner describes ASPM tools as systems that ingest data from multiple SDLC
  sources, maintain software inventory, correlate findings, and prioritize
  remediation. AppGuardrail's org failure collector is a first IssueOps step in
  this direction. Source:
  https://www.gartner.com/reviews/market/application-security-posture-management-aspm-tools
- OWASP SAMM organizes security maturity into 15 practices across 5 business
  functions. AppGuardrail should map product evidence to governance, design,
  implementation, verification, and operations. Source:
  https://owaspsamm.org/about/
- OWASP Top 10, MITRE CWE, and CISA KEV provide the external language for
  severity, education, and prioritization. AppGuardrail should map findings to
  these references without turning product advisories into noisy regex rules.
  Sources: https://owasp.org/www-project-top-ten/,
  https://cwe.mitre.org/, https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Semgrep's public rules and taint-mode model show why AppGuardrail should use
  external engines for deep interprocedural detection, while keeping
  beginner-safe built-in checks for fast first value. Sources:
  https://github.com/semgrep/semgrep-rules,
  https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview

## Product Thesis

AppGuardrail should become the security operating layer for AI-built apps:

1. The CLI gives a beginner a useful result in less than 5 minutes.
2. The core library normalizes rules, language detection, external engine
   results, and remediation metadata.
3. The IssueOps layer turns CI failures, Strix/OpenCode/AppGuardrail findings,
   and security logs into deduplicated issues that teams can act on.
4. The report layer turns technical findings into founder, agency, and buyer
   diligence deliverables.
5. The future hosted control plane gives teams a dashboard for repository
   posture, triage, and remediation progress without requiring them to become
   AppSec specialists.

## Architecture Decision

Separate library work is appropriate, but a Git submodule is not the right first
move.

Decision:

- Keep one repository for now.
- Introduce an in-repo `appguardrail_core` package when implementation begins.
- Keep the existing `scanner.cli.appguardrail` CLI as the compatibility entry
  point.
- Move reusable domain logic into `appguardrail_core` only when it has at least
  two consumers: CLI, tests, future web/API worker, report generator, or org
  collector.
- Avoid a Git submodule until there is a hard boundary such as an independently
  versioned commercial engine, a separate SDK repository, or a licensing split.

Why:

- Submodules increase setup friction for beginner users and CI maintainers.
- The current package is small and alpha-stage; premature repo splitting would
  slow scanner and UX iteration.
- An in-repo core package gives clean API boundaries while preserving one
  release, one test suite, and one issue tracker.

Target core boundaries:

- `appguardrail_core.language`: file inventory and language/framework profile
  detection.
- `appguardrail_core.rules`: built-in rule loading, metadata validation, CWE /
  OWASP / KEV references, severity policy.
- `appguardrail_core.findings`: normalized finding schema, deduplication,
  deploy-blocking policy, SARIF/JSON output.
- `appguardrail_core.external`: adapters for Bandit, Ruff, Semgrep, Trivy,
  CodeQL evidence imports, and ZAP baseline runs.
- `appguardrail_core.issueops`: redaction, CI log compression, issue markers,
  duplicate suppression.
- `appguardrail_core.reports`: founder-friendly, agency, fix-pack, and buyer
  diligence reports.

## Beginner-Safe Language Profiles

Users should run `appguardrail scan .` and get the union of relevant checks.
They should not need to select a profile.

### Python + Web

Detection inputs:

- `.py`, `pyproject.toml`, `requirements.txt`, `Pipfile`, `poetry.lock`
- Flask, Django, FastAPI, Starlette, Jinja2, requests, PyYAML, SQLAlchemy
- HTML/templates and web config files when present

Default coverage:

- Built-in Python/web patterns: unsafe deserialization, `requests(...,
  verify=False)`, Flask debug, Jinja autoescape off, CSRF exemptions, predictable
  temp files, hardcoded secrets, CORS wildcards, exposed admin routes.
- External auto mode: Bandit and Ruff security rules when installed, Semgrep
  when runnable, Trivy filesystem scan when requested or configured.
- ZAP baseline only when an authorized URL is supplied by `--zap-baseline` or
  `APPGUARDRAIL_TARGET_URL`.

### Java Only

Detection inputs:

- `.java`, `pom.xml`, `build.gradle`, `settings.gradle`, `gradle.lockfile`
- Spring Security, servlet filters, JWT libraries, Jackson serialization,
  Maven/Gradle dependencies

Default coverage:

- Built-in Java patterns: Spring CSRF disabled, allow-all hostname verifier,
  native deserialization entry points, JWT `none`, insecure cookie flags,
  hardcoded secrets, risky CORS/security header disables.
- External auto mode: Semgrep when runnable, Trivy for dependency/IaC/container
  evidence when configured, CodeQL SARIF import when a workflow artifact exists.

### Java + Node.js + TypeScript

Detection inputs:

- Java inputs plus `package.json`, `pnpm-lock.yaml`, `yarn.lock`,
  `package-lock.json`, `.ts`, `.tsx`, `.js`, `.jsx`
- Express, Next.js, NestJS, React, Vite, JWT, CORS, Helmet, Stripe, Firebase,
  Supabase

Default coverage:

- Merge Java, JavaScript, TypeScript, and web axes; do not create a special
  combo preset.
- Detect monorepo workspaces and scan package boundaries independently.
- Prioritize cross-service risks: public CORS with credentials, disabled TLS,
  missing JWT verification, client-exposed secrets, webhook signature bypass,
  server action/API route auth gaps, insecure cookie/session settings.

### Language-Agnostic CI Failure Logs

Status note (2026-08-09): this section records target architecture. The current
fleet collector is metadata-only and does not fetch or publish raw/compressed
job logs. Log classification is a bounded RCA hint, not direct detector
efficacy; source-bound probes and independent oracles remain required.

Detection inputs:

- GitHub Actions run/job logs from Strix, OpenCode, AppGuardrail, Trivy, CodeQL,
  and Security Process workflows.
- Known failure strings such as `VULN-`, `::error::`, `Unable to map Strix
  findings`, `RateLimitError`, `CRITICAL`, `HIGH`, and timeout markers.

Default coverage:

- Redact tokens, keys, JWTs, and Authorization headers.
- Store deduplication markers per repository, workflow, run, and job.
- Create or reopen AppGuardrail issues by `repo + workflow`.
- Keep compressed logs in issues and preserve raw GitHub Actions links.

## Product Design Plan

The sellable product surface must be useful on first screen. No marketing-only
landing page should be the primary experience.

Primary screens:

- Repository posture overview: risk by repo, language, workflow, owner, and age.
- Scan run detail: findings grouped by deploy blocker, language, CWE/OWASP, and
  remediation owner.
- IssueOps inbox: Strix/OpenCode/AppGuardrail/Trivy/CodeQL failures grouped by
  recurring workflow and deduplicated run/job evidence.
- Beginner onboarding: one command, detected stack, next action, and safe
  explanation of why a finding matters.
- Report builder: founder report, agency handoff, buyer diligence export, and
  fix-pack export.
- Settings: GitHub App permissions, authorized ZAP targets, redaction policy,
  external engine availability, and data retention.

Figma scope without Code Connect:

- Create a Figma file or equivalent design spec for the screens above.
- Use component names that map to product concepts, not implementation classes.
- Include empty, loading, redacted, partial-permission, no-findings, and
  high-risk states.
- Do not use Figma Code Connect in this workstream.

## Data Analytics Plan

North-star metric:

- Weekly repositories with at least one AppGuardrail-confirmed risk reduced or
  prevented.

Activation metrics:

- Time from install to first useful finding: target under 5 minutes.
- Percent of first scans requiring no language/profile flags: target above 95%.
- Percent of scans with actionable next step in output: target above 95%.

Detection quality metrics:

- Built-in fixture precision for deploy-blocking findings: target above 90%.
- Duplicate CI failure issue suppression: target above 99% on replay tests.
- Redaction regression tests for tokens/JWTs/Authorization: target 100% pass.
- External-engine fallback clarity: missing optional tools should explain what
  was skipped without failing auto mode.

Commercial readiness metrics:

- 3 pilot organizations or internal org equivalents scanned weekly.
- 20 active repositories under monitoring.
- 50 recurring security failures automatically grouped into actionable issues.
- 10 founder-friendly reports generated from real scans.
- 5 buyer-diligence exports generated without manual editing.

First implementation slice:

- Added `appguardrail_core.metrics` as the reusable KPI scoring boundary.
- Encodes activation, detection quality, and commercial readiness targets from
  this plan in `score_sale_readiness(inputs)`.
- Returns `sale-ready`, `pilot-ready`, or `not-ready` plus unmet KPI detail so
  the future dashboard, reports, and release checks can share one contract.
- Treats time-to-first-finding, zero-config scans, fixture precision, redaction,
  and buyer diligence exports as critical gaps that block sale-readiness even
  when most softer metrics pass.

## Packaging And Pricing Hypotheses

Open-source base:

- Free CLI, built-in rules, report templates, and GitHub Actions monitor.
- Purpose: trust, distribution, and reproducible security education.

Team package:

- Hosted dashboard, org-wide IssueOps, report exports, scheduled scans, and
  external engine orchestration.
- Buyer: agencies, AI app studios, small SaaS teams.

Enterprise package:

- GitHub App install, audit trail, retention controls, SSO-ready architecture,
  advanced triage, policy exceptions, and buyer diligence evidence.
- Buyer: organizations adopting AI-assisted development at scale.

The pricing proof should compare against per-active-committer security products,
but the sales message should be outcome-based: fewer launch blockers, faster
security triage, and buyer-ready evidence for AI-built apps.

## Execution Workstreams

### WS0: Product Readiness Baseline

Deliverables:

- This sale-readiness plan in `docs/product/`.
- README link from the public documentation surface.
- Public roadmap issue or PR body with milestones and acceptance criteria.

Acceptance:

- The repo states what AppGuardrail is becoming, why it is commercially
  distinct, and what is required before 2B KRW sale readiness can be argued.

### WS1: Core Library Split

Deliverables:

- Add `appguardrail_core` package inside this repo.
- Move language detection, finding schema, redaction/compression, and rule
  metadata validation behind stable functions.
- Keep `appguardrail` CLI behavior backward compatible.

Acceptance:

- Existing tests pass.
- New unit tests cover core APIs directly.
- CLI output remains compatible for current users.
- No Git submodule is introduced.

First implementation slices:

- Added `appguardrail_core.issueops` for redaction, log compression, issue
  markers, title/body/comment formatting, and duplicate suppression.
- Added `appguardrail_core.findings` for normalized finding defaults, severity
  counts, deploy-blocking policy, report-safe snippets, and stable sorting.
- Kept scanner compatibility wrappers where tests or current CLI behavior import
  private helpers directly, while moving shared policy into core.

### WS2: Language Profile Matrix

Deliverables:

- Structured language/framework detection matrix.
- Python web, Java, JavaScript/TypeScript, and mixed-stack profile tests.
- External engine availability report in scan output.

First implementation slice:

- Added `appguardrail_core.language` as the reusable zero-config profile
  boundary.
- Detects language axes from both source files and common manifests, so a
  beginner does not have to choose `python`, `java`, or `typescript` before the
  first scan.
- Covers the requested first profiles: Python web, Java-only, and Java +
  Node.js/TypeScript.
- Prints a beginner-facing profile summary and optional external engine plan
  from `appguardrail scan .` while preserving existing CLI behavior.
- Added `appguardrail_core.external` as the external SAST/DAST planning
  boundary for Bandit, Ruff, Semgrep, Trivy, and ZAP.
- Auto mode now produces a tested run/skip plan from detected languages and
  tool availability; missing optional engines are explained without failing the
  beginner's first scan, while explicitly forced engines still fail loudly.

Acceptance:

- `appguardrail scan .` works without flags for Python web, Java-only, and
  Java+Node+TypeScript fixtures.
- Optional engines are skipped cleanly in auto mode and fail loudly when forced.

### WS3: Rule Knowledge Base

Deliverables:

- Rule metadata schema with CWE, OWASP Top 10, SAMM practice, source, and
  remediation prompt fields.
- Keep CVE/KEV as prioritization and dependency/SCA references, not raw regex
  sources.
- Add validation tests that block rules without required metadata.

First implementation slice:

- Added `appguardrail_core.rules` with a normalized `RuleMetadata` envelope.
- Extracts public OWASP/CWE/CVE references already present in rule copy and
  adds conservative category defaults when rule copy does not yet include an
  explicit taxonomy reference.
- Attaches `references`, `owasp`, `cwe`, `samm_practice`, and `remediation` to
  every normalized finding emitted by scanner providers.
- Added validation tests so report-generation code can reject findings that
  lack public taxonomy or remediation metadata.

Acceptance:

- Every built-in rule has traceable metadata.
- Reports can group findings by risk category and buyer-friendly explanation.

### WS4: IssueOps And Org Collector Productization

Deliverables:

- Extract collector redaction, compression, and marker parsing into core.
- Add replay fixtures for Strix/OpenCode/AppGuardrail/Trivy/CodeQL logs.
- Add issue comment templates oriented around beginner triage.

First implementation slice:

- Extracted reusable IssueOps helpers into `appguardrail_core.issueops`.
- Kept the GitHub collector as orchestration code only.
- Preserved duplicate suppression, redaction, compressed comments, and Strix
  run URL handling through focused tests.

Acceptance:

- The known Strix failure URL pattern is represented by tests.
- Replay does not create duplicate issue comments.
- Redaction tests cover token, JWT, Authorization, and API key patterns.

### WS5: Control Plane UX And Figma

Deliverables:

- Figma file or design spec for posture overview, scan detail, IssueOps inbox,
  onboarding, report builder, and settings.
- No Figma Code Connect.
- Product copy for beginner-safe explanations and enterprise trust states.

Acceptance:

- Design states cover empty, loaded, high-risk, redacted, partial-permission,
  no-findings, and external-tool-missing conditions.
- The design can be implemented without inventing new product concepts.

### WS6: Reports And Buyer Diligence

Deliverables:

- Buyer diligence report template.
- Founder/agency/fix-pack exports backed by normalized findings.
- Release, license, dependency, and privacy notes.

First implementation slice:

- Added `appguardrail_core.reports` with
  `render_buyer_diligence_report(findings, context)`.
- Generates an executive readout, scope/evidence handling section, findings
  summary, detailed findings, and buyer follow-up checklist from normalized
  findings.
- Uses deploy-blocking context, public taxonomy metadata, remediation, and
  verification fields without including raw secrets or full logs.
- Added `reports/templates/buyer-diligence.md` to document the generated report
  structure expected by the Product Design report-builder surface.
- Added `appguardrail report buyer-diligence --findings findings.json` so a
  pilot user or diligence reviewer can generate the markdown export from a
  findings JSON file without writing Python code.
- Added `appguardrail scan --findings-json reports/findings.json` so scan
  evidence can feed diligence reports and future dashboards without manual JSON
  assembly.
- Added `appguardrail report founder-friendly`, `agency`, and `fix-pack`
  exports backed by the same normalized findings JSON contract:
  - founder-friendly: plain-language launch readiness and copy/paste fix
    prompts for non-security founders.
  - agency: client-ready methodology, severity sections, priority matrix, and
    retest notes.
  - fix-pack: AI-ready remediation work items and verification tests.

Acceptance:

- A pilot buyer can see what was scanned, what was found, what was fixed, what
  remains accepted risk, and how evidence maps to OWASP/CWE/SAMM.

### WS6.5: Product Metrics And Diligence Scorecard

Deliverables:

- Add a core KPI model for activation, quality, and commercial readiness.
- Expose a sale-readiness score that can feed reports, dashboards, and release
  discipline without copying thresholds into each surface.
- Keep analytics privacy-preserving by accepting aggregate counts and rates
  instead of raw code, raw logs, or user-identifying event streams.

First implementation slice:

- Added `SaleReadinessInputs`, `MetricResult`, `SaleReadinessScore`, and
  `score_sale_readiness` in `appguardrail_core.metrics`.
- Added tests for all-pass sale readiness, pilot-ready noncritical gaps,
  critical buyer/readiness gaps, and strict threshold behavior.

Acceptance:

- Product readiness can be measured with a deterministic, tested API.
- KPI gaps are explicit enough for a founder, pilot buyer, or diligence reviewer
  to see what blocks the 2B KRW sale-readiness argument.

### WS7: Merge And Release Discipline

Deliverables:

- PRs remain small enough to review quickly.
- Each PR includes tests or explicit no-code validation.
- Merge when checks pass and no actual technical blocker remains.

Acceptance:

- Review waiting alone does not stop delivery.
- Branch protection, CI failures, permissions, or external service failures are
  treated as real blockers and documented.

## Immediate Next PR Slices

1. Merge this plan and README link.
2. Add `appguardrail_core.issueops` by extracting redaction, log compression,
   marker parsing, and duplicate key behavior from the org collector.
3. Add `appguardrail_core.language` with fixture-backed detection for Python
   web, Java-only, and Java+Node+TypeScript.
4. Add a rule metadata schema and migrate existing built-in rule definitions to
   include CWE/OWASP/SAMM/source/remediation fields.
5. Add a buyer diligence report template fed by normalized findings.
6. Create the no-Code-Connect Figma design artifact or, if Figma tools remain
   unavailable, maintain the design spec in repo until the file can be created.

## Definition Of 2B KRW Sale Readiness

AppGuardrail reaches the target standard when all of the following are true:

- A buyer can understand the product in one command, one dashboard, and one
  diligence report.
- The scanner is beginner-safe across Python web, Java, and Java+Node/TypeScript
  without profile selection.
- Built-in findings are traceable to public security references.
- External engines add depth without becoming mandatory setup.
- Org security workflow failures are collected, redacted, deduplicated, and
  turned into actionable issues.
- Product metrics show first value, quality, adoption, and remediation outcomes.
- The repo has a clear core boundary that supports future hosted or commercial
  packaging without submodule friction.
- There is enough design, documentation, tests, and release discipline for a
  diligence reviewer to see repeatable execution rather than a one-off script.
