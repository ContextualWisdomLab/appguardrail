# Code Scanning Analysis Drift Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect when a pull request loses a Code Scanning tool/category analysis that is present on its base branch, and publish one bounded, auditable IssueOps record without confusing repository-local workflow heuristics with live GitHub analysis state.

**Architecture:** Add a dependency-free core module that normalizes GitHub analysis payloads into stable identities and compares complete base/current snapshots fail-closed. Add a bounded organization collector that obtains exact-head evidence from GitHub REST, emits machine-readable unknown states for permission/service/malformed responses, and publishes only confirmed drift through dedicated IssueOps markers. Reuse the existing GitHub App trust boundary and target-only issue writer in the organization security collector workflow.

**Tech Stack:** Python 3.11+, standard library dataclasses/urllib/json/hashlib, GitHub REST API 2022-11-28, pytest, GitHub Actions.

## Global Constraints

- Do not use the deprecated top-level `tool_name`; read `tool.name` and optional `tool.guid`.
- A drift finding requires complete pagination, nonempty healthy base evidence, and exact current PR head or merge-ref evidence.
- HTTP 403, 404, 503, pagination failure, malformed payload, or incomplete exact-head evidence returns an explicit unknown state and never publishes a missing-configuration finding.
- Preserve analysis `error` and `warning`; an errored current analysis is not equivalent to a healthy base analysis.
- Keep live drift issues distinct from `github-actions-sarif-missing-pull-request-trigger` repository-source findings.
- New public modules, classes, functions, methods, and properties require explanatory docstrings and 100% statement/branch coverage.
- Preserve standalone operation and modular use from central ContextualWisdomLab governance workflows and naruon-compatible service composition.
- No database objects are introduced.

---

### Task 1: Stable analysis identity and fail-closed comparison

**Files:**
- Create: `appguardrail_core/code_scanning.py`
- Modify: `appguardrail_core/__init__.py`
- Test: `tests/test_code_scanning_core.py`

**Interfaces:**
- Produces: `AnalysisIdentity`, `AnalysisEvidence`, `AnalysisSnapshot`, `DriftAssessment`, `normalize_analysis()`, `build_snapshot()`, `compare_snapshots()`.
- Consumes: GitHub analysis dictionaries from the REST endpoint.

- [ ] **Step 1: Write failing tests for identity normalization**

Cover `tool.name`, optional `tool.guid`, `category`, stable `analysis_key`/`environment`, deprecated `tool_name` rejection, matrix-dimension preservation, volatile SHA/ref normalization, malformed payload rejection, and deterministic ordering.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -m pytest tests/test_code_scanning_core.py -q`

Expected: import failure because `appguardrail_core.code_scanning` does not exist.

- [ ] **Step 3: Implement immutable analysis models and normalization**

Use frozen dataclasses, bounded strings, full-match validation for 40-character commit SHAs, UTC-sortable timestamps, and deterministic identity serialization.

- [ ] **Step 4: Add failing comparison tests**

Cover clean parity, absent current analysis, errored current analysis, warning preservation, empty base evidence, incomplete pages, exact-ref mismatch, exact-head mismatch, duplicate analyses, and latest-analysis selection.

- [ ] **Step 5: Implement snapshot construction and comparison**

Return `clean`, `drift`, or `unknown`; do not infer drift from unknown evidence.

- [ ] **Step 6: Run focused tests and confirm GREEN**

Run: `python -m pytest tests/test_code_scanning_core.py -q`

Expected: all focused tests pass.

### Task 2: Paginated GitHub-state collector

**Files:**
- Create: `scripts/ci/collect_code_scanning_drift.py`
- Test: `tests/test_code_scanning_drift_collector.py`

**Interfaces:**
- Consumes: distinct read/write GitHub App installation tokens, reviewed repository allowlist, open pull requests, base/head metadata, and Code Scanning analyses.
- Produces: bounded `DriftRecord` values and machine-readable JSON summaries.

- [ ] **Step 1: Write failing transport tests**

Cover fixed `https://api.github.com` origin, redirect rejection, 100-item pagination, list-shape validation, 403/404/503 classification, other HTTP/API errors, exact repository syntax, and separate read/write credentials.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/test_code_scanning_drift_collector.py -q`

Expected: import failure because the collector does not exist.

- [ ] **Step 3: Implement the minimal REST client and page result model**

The client must never follow redirects with credentials and must surface classified unknown states without logging secrets.

- [ ] **Step 4: Write failing collection tests**

Cover open-PR enumeration, `refs/heads/<base>` queries, `pr=<number>` queries, `refs/pull/<number>/merge`, head and merge SHA acceptance, archived/fork filtering, repository allowlists, global PR bounds, and central required-workflow analyses represented by live API evidence.

- [ ] **Step 5: Implement bounded collection**

Collect at most the configured number of open PRs, compare exact-head snapshots, and preserve unknown outcomes in the JSON summary while returning only confirmed drift records for publication.

- [ ] **Step 6: Run focused tests and confirm GREEN**

Run: `python -m pytest tests/test_code_scanning_drift_collector.py -q`

Expected: all focused tests pass.

### Task 3: Dedicated IssueOps publication

**Files:**
- Modify: `scripts/ci/collect_code_scanning_drift.py`
- Test: `tests/test_code_scanning_drift_issueops.py`

**Interfaces:**
- Produces: stable issue title, hidden marker, bounded body, and deduplicated updates keyed by repository, PR number, exact head SHA, and missing normalized identities.

- [ ] **Step 1: Write failing IssueOps tests**

Cover one issue per exact PR head, normalized identity sorting, repeat-run deduplication, reopening only the matching head issue, dedicated labels, issue-body bounds, unknown-state nonpublication, and distinct identity from repository-local SARIF trigger findings.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/test_code_scanning_drift_issueops.py -q`

Expected: failures for missing publisher helpers.

- [ ] **Step 3: Implement bounded publishing**

Use a dedicated `code-scanning-drift` marker and label; include evidence URLs/refs/SHAs, missing or errored identities, remediation, and the explicit statement that this is live GitHub-state evidence rather than source-configuration inference.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run: `python -m pytest tests/test_code_scanning_drift_issueops.py -q`

Expected: all focused tests pass.

### Task 4: Organization workflow integration

**Files:**
- Modify: `.github/workflows/org-security-failure-collector.yml`
- Test: `tests/test_code_scanning_drift_workflow.py`

**Interfaces:**
- Consumes: the existing reviewed repository allowlist and target-only issue writer.
- Produces: a scheduled drift collection step after workflow-failure collection.

- [ ] **Step 1: Write failing workflow contract tests**

Require full-SHA-pinned actions, `persist-credentials: false`, separate tokens, `permission-pull-requests: read`, `permission-security-events: read`, target-only `permission-issues: write`, the reviewed repository allowlist output, and the drift collector invocation.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/test_code_scanning_drift_workflow.py -q`

Expected: failures because the workflow lacks Code Scanning and PR read permissions and the new step.

- [ ] **Step 3: Add least-privilege workflow wiring**

Pass the validated comma-separated repository allowlist to the collector. Keep schedule/repository-dispatch default-branch trust and existing failure collector behavior unchanged.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run: `python -m pytest tests/test_code_scanning_drift_workflow.py -q`

Expected: all focused tests pass.

### Task 5: Documentation, backlog handoff, and full verification

**Files:**
- Create: `docs/code-scanning-analysis-drift.md`
- Create: `CHANGELOG.d/862-code-scanning-analysis-drift.md`
- Modify: `scripts/ci/commercial_readiness_loop.py`
- Test: existing commercial-readiness and docstring/coverage suites.

**Interfaces:**
- Documents permissions, statuses, evidence boundaries, remediation, and operational commands.
- Removes the completed `github-code-scanning-analysis-drift` gap and retains the next reviewed buyer-visible gaps.

- [ ] **Step 1: Document operator and buyer-facing behavior**

Explain `clean`/`drift`/`unknown`, exact-head requirements, GitHub App permissions, central required workflows, deduplication, non-overlap with the local SARIF rule, and privacy boundaries.

- [ ] **Step 2: Update the reviewed backlog and changelog fragment**

Remove only the completed gap from `COMMERCIAL_GAPS`; do not close #310/#311 unless live repository evidence is present in the implementation PR.

- [ ] **Step 3: Run full verification**

Run: `python -m pytest -q`

Run the repository's docstring and 100% statement/branch coverage gates through the exact current-head GitHub Checks.

- [ ] **Step 4: Self-scan and package verification**

Run the required AppGuardrail deploy gate, SAST, Security Scan, build, and package metadata checks on the exact head.

- [ ] **Step 5: Open a draft PR, review every thread, and merge only after exact-head gates succeed**

The PR body must include `Closes #862`, evidence limits, test results, and explicit nonclosure of #310/#311 unless live evidence justifies it.
