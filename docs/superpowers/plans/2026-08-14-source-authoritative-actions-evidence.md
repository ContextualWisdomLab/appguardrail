# Source-Authoritative GitHub Actions Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one production-grade detector vertical slice that independently acquires a GitHub Actions run and job, verifies their source identity, classifies the security outcome, and emits reproducible evidence instead of trusting a caller-provided Boolean or log label.

**Architecture:** A new dependency-free `appguardrail_core.github_actions_evidence` module owns strict GitHub REST acquisition, schema and identity validation, canonical source hashing, duplicate protection, and a CLI entrypoint. The existing IssueOps collector remains the organization-wide publisher; the new entrypoint is a bounded production verifier for exact run/job evidence and provides the contract that later collector integration can reuse. All network requests remain pinned to `https://api.github.com`, reject redirects, cap response size, and never emit the token.

**Tech Stack:** Python 3.11+, standard-library `argparse`, `dataclasses`, `datetime`, `hashlib`, `json`, `urllib`; pytest; setuptools console scripts.

## Global Constraints

- Production statement coverage and branch coverage for the new module must be 100%.
- Every public module, class, function, method, and error type must have a complete docstring.
- Database and persistent object names, when introduced, must contain at least two words and use `snake_case`; this slice introduces no database object.
- GitHub source URLs and API origin are HTTPS-only and fail closed on redirect or identity mismatch.
- The verifier must preserve authorized evidence metadata without indiscriminate PII masking; it emits only bounded Actions metadata and never the bearer token or raw cross-repository logs.
- No external runtime dependency may be added.
- Historical issues #815, #813, and #763 are regression shapes, not self-authenticating oracles.

---

### Task 1: Define the source-evidence contract with failing tests

**Files:**
- Create: `tests/test_github_actions_evidence.py`
- Create later: `appguardrail_core/github_actions_evidence.py`

**Interfaces:**
- Produces: wished-for `verify_actions_job(repository, run, job, observed_at, max_age, seen_source_digests)` and `EvidenceValidationError` interfaces.
- Consumes: `appguardrail_core.issueops.is_failure` and `appguardrail_core.issueops.is_security_name`.

- [ ] **Step 1: Write a failing historical-failure test**

Create a #815-shaped run/job fixture and assert that verification returns `detector_state == "failure"`, exact run/job identity, `probe_ref == "github_actions_job_v1"`, `acquirer_ref == "github_rest_api_v2022_11_28"`, and a 64-character SHA-256 source digest.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `pytest -q tests/test_github_actions_evidence.py::test_verifies_source_authoritative_failure`

Expected: collection failure because `appguardrail_core.github_actions_evidence` does not exist.

- [ ] **Step 3: Add identity and fail-closed tests**

Cover success, cancelled security run, non-security job, mismatched run/job IDs, malformed SHA, wrong-origin URLs, unfinished jobs, stale evidence, duplicate digest, non-object payload, oversized IDs, and a stable digest across mapping key order.

- [ ] **Step 4: Re-run and retain RED evidence**

Run: `pytest -q tests/test_github_actions_evidence.py`

Expected: collection failure for the missing production module.

- [ ] **Step 5: Commit the RED tests**

```bash
git add tests/test_github_actions_evidence.py docs/superpowers/plans/2026-08-14-source-authoritative-actions-evidence.md
git commit -m "test(actions): define source-authoritative evidence contract"
```

### Task 2: Implement deterministic source verification

**Files:**
- Create: `appguardrail_core/github_actions_evidence.py`
- Test: `tests/test_github_actions_evidence.py`

**Interfaces:**
- Produces: `ActionsJobEvidence`, `EvidenceValidationError`, `verify_actions_job`, and `ensure_unique_source_digest`.
- Consumes: exact GitHub run and job mappings acquired by Task 3.

- [ ] **Step 1: Implement strict scalar and URL validation**

Validate repository names as exactly two bounded GitHub name segments; require positive run/job IDs of at most 20 digits; require exact GitHub run/job HTTPS URLs; require a 40-character hexadecimal head SHA; require timezone-aware GitHub timestamps; and reject incomplete or unknown conclusions.

- [ ] **Step 2: Implement canonical evidence projection and hashing**

Project only bounded run/job fields plus step number/name/status/conclusion, encode with sorted compact JSON, and compute SHA-256. Never include authorization headers, tokens, annotations, or raw logs.

- [ ] **Step 3: Implement classification and freshness**

Classify GitHub failure conclusions as `failure`, completed `success` as `pass`, and reject unsupported conclusions. Require security-relevant workflow/job names and enforce `updated_at <= observed_at` plus the configured maximum age.

- [ ] **Step 4: Implement immutable result serialization and duplicate rejection**

Return a frozen dataclass with `to_dict()` and reject a digest already present in the caller-supplied digest set.

- [ ] **Step 5: Run the focused suite and verify GREEN**

Run: `pytest -q tests/test_github_actions_evidence.py`

Expected: all tests pass.

- [ ] **Step 6: Commit the verifier**

```bash
git add appguardrail_core/github_actions_evidence.py tests/test_github_actions_evidence.py
git commit -m "feat(actions): verify source-authoritative job evidence"
```

### Task 3: Add bounded GitHub REST acquisition and CLI execution

**Files:**
- Modify: `appguardrail_core/github_actions_evidence.py`
- Modify: `tests/test_github_actions_evidence.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `GitHubApiClient`, `acquire_actions_job`, and `main`.
- Consumes: `verify_actions_job` from Task 2.

- [ ] **Step 1: Write RED client tests**

Use a fake opener/response to prove the client rejects redirects, non-JSON content, payloads larger than 2 MiB, non-object JSON, and source identity mismatch; prove the token is sent only in the Authorization request header and never appears in output.

- [ ] **Step 2: Run the new client tests and verify RED**

Run: `pytest -q tests/test_github_actions_evidence.py -k "client or cli or acquire"`

Expected: failures because the acquisition and CLI interfaces are missing.

- [ ] **Step 3: Implement the pinned REST client and acquisition**

GET `/repos/{repository}/actions/runs/{run_id}` and `/repos/{repository}/actions/jobs/{job_id}` through a no-redirect opener, a 30-second timeout, GitHub API version `2022-11-28`, and a 2 MiB response cap. Pass both mappings to `verify_actions_job`.

- [ ] **Step 4: Implement the CLI**

Require `--repository`, `--run-id`, and `--job-id`; read only `APPGUARDRAIL_GITHUB_TOKEN`; support `--max-age-hours` and `--seen-source-digest`; emit sorted JSON. Exit 0 for verified pass, 1 for verified security failure, and 2 for acquisition or validation failure.

- [ ] **Step 5: Register the console script**

Add `appguardrail-actions-evidence = "appguardrail_core.github_actions_evidence:main"` to `[project.scripts]`.

- [ ] **Step 6: Run focused and full tests**

Run: `pytest -q tests/test_github_actions_evidence.py`

Run: `pytest -q`

Expected: all tests pass with no warnings.

- [ ] **Step 7: Commit the production entrypoint**

```bash
git add appguardrail_core/github_actions_evidence.py tests/test_github_actions_evidence.py pyproject.toml
git commit -m "feat(actions): add evidence acquisition CLI"
```

### Task 4: Add audit, threat, operations, and traceability documentation

**Files:**
- Create: `docs/github-actions-source-evidence.md`
- Create: `docs/adr/0007-source-authoritative-actions-evidence.md`
- Create: `CHANGELOG.d/938-source-authoritative-actions-evidence.md`
- Modify: `ARCHITECTURE.md`
- Modify: `docs/TEST_STRATEGY.md`
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/OPERABILITY.md`
- Modify: `docs/TRACEABILITY.md`

**Interfaces:**
- Documents: the exact CLI, evidence schema, exit codes, trust boundary, replay procedure, and buyer-visible acceptance evidence.

- [ ] **Step 1: Document the evidence flow**

Show `repository/run/job identity → pinned GitHub REST acquisition → strict validation → canonical digest → pass/failure decision → JSON evidence`, and distinguish the GitHub API response from historical AppGuardrail issue text.

- [ ] **Step 2: Document threats and controls**

Cover confused-deputy repository substitution, cross-origin redirects, ID mismatch, stale/replayed evidence, oversized payloads, token disclosure, untrusted job names, and incomplete jobs.

- [ ] **Step 3: Document testing and operations**

Provide exact commands for historical replay, token scope, exit-code handling, duplicate-ledger integration, incident diagnosis, and rollback.

- [ ] **Step 4: Add APA 7th references**

Cite GitHub REST API documentation, NIST SP 800-53 Rev. 5 evidence/audit controls, NIST SP 800-218 SSDF, SLSA v1.2, and RFC 8259 where each decision is applied.

- [ ] **Step 5: Update traceability and changelog**

Map issue #938 acceptance criteria to production symbols and tests; describe the feature as one verified vertical slice rather than complete coverage of every AppGuardrail issue family.

- [ ] **Step 6: Commit documentation**

```bash
git add ARCHITECTURE.md docs CHANGELOG.d/938-source-authoritative-actions-evidence.md
git commit -m "docs(actions): trace source-authoritative evidence slice"
```

### Task 5: Enforce exact quality gates and open the PR

**Files:**
- Modify only if required: `.github/workflows/tests.yml`
- Verify: `.github/workflows/github-actions-evidence-coverage.yml` and all files changed in Tasks 1-4.

**Interfaces:**
- Produces: exact-head CI evidence and a reviewable PR linked to issue #938.

- [ ] **Step 1: Run module coverage and docstring gates**

Run: `coverage run --branch -m pytest -q tests/test_github_actions_evidence.py`

Run: `coverage report --include='appguardrail_core/github_actions_evidence.py' --fail-under=100`

Run: `interrogate -vv appguardrail_core/github_actions_evidence.py`

Expected: 100% statement/branch coverage and 100% docstrings.

- [ ] **Step 2: Run repository validation**

Run: `python -m compileall -q appguardrail_core scanner scripts tests`

Run: `pytest -q`

Run: `python -m build`

Expected: all commands succeed without warnings, and the dedicated `GitHub Actions Evidence Coverage` workflow is required on the exact PR head.

- [ ] **Step 3: Open a bounded PR**

Use title `feat(actions): verify source-authoritative job evidence` and link `Closes #938`. Keep auto-merge disabled until independent review and exact-head checks pass.

- [ ] **Step 4: Process review and merge gates**

Resolve only verified findings, rerun exact-head checks, obtain approval from someone other than the latest pusher, enable auto-merge, and confirm the protected `develop` commit after merge.
