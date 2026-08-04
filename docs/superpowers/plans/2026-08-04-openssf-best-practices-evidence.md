# OpenSSF Best Practices Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn OpenSSF Best Practices participation into conservative, auditable evidence that AppGuardrail can collect, normalize, and include in buyer-diligence reports.

**Architecture:** Add a dependency-free core module that parses exact repository-URL search responses from the official current and legacy OpenSSF Best Practices origins into an immutable evidence record. Keep transport classification separate from payload parsing, convert every state into one normalized governance finding, expose an offline-capable CLI command, and render the same metadata in buyer-diligence output. Unknown, inaccessible, or malformed evidence remains explicit and never becomes a claim of non-registration.

**Tech Stack:** Python 3.9+, standard-library `urllib`, `json`, `dataclasses`, existing AppGuardrail findings/report contracts, pytest, existing exact statement-coverage tracer.

## Global Constraints

- Use only `https://www.bestpractices.dev` and `https://bestpractices.coreinfrastructure.org` as evidence-service origins.
- Query the official exact-URL search endpoint `/projects.json?url=<repository-url>`; do not scrape HTML.
- Recognize only `in_progress`, `passing`, `silver`, and `gold` badge levels.
- Treat empty results as `unavailable`, not proof that a project is unregistered.
- Treat permission responses, malformed payloads, ambiguous matches, and network/service failures as explicit non-affirmative states.
- Keep the collector usable as a standalone library and through the AppGuardrail CLI without adding third-party dependencies.
- Preserve 100% statement coverage and complete docstrings for all new production code.
- Update user documentation and a changelog fragment; do not bump the package version until the complete release candidate is validated.
- Preserve the hourly PR-first commercial-readiness loop and advance its bounded registry to the next buyer-visible gap.

---

### Task 1: Evidence Model And Parser

**Files:**
- Create: `appguardrail_core/openssf_evidence.py`
- Test: `tests/test_openssf_evidence.py`

**Interfaces:**
- Produces: `OpenSSFEvidence`, `parse_project_matches(payload, *, repository_url, verified_at, source_origin)`, `evidence_to_finding(evidence)`.
- Consumes: JSON-decoded payloads from official OpenSSF project-search endpoints.

- [ ] **Step 1: Write failing parser and finding tests**

Cover exact parsing for `in_progress`, `passing`, `silver`, and `gold`; empty arrays; non-list payloads; multiple matches; invalid identifiers; unknown tiers; Boolean-as-integer rejection; deterministic timestamps; conservative messages; and normalized custom evidence fields.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/test_openssf_evidence.py -q`
Expected: collection error because `appguardrail_core.openssf_evidence` does not exist.

- [ ] **Step 3: Implement the immutable model and pure parser**

Use a frozen dataclass. Validate repository URL, source origin, project identifier, tier, and optional tiered percentage. Generate canonical evidence URLs as `https://www.bestpractices.dev/projects/<id>` and never infer a tier from percentages.

- [ ] **Step 4: Convert evidence to normalized governance findings**

Emit rule `openssf-best-practices-evidence`, category `supply-chain`, context `governance`, conservative INFO/WARNING severities, official references, and custom fields for status, tier, URL, verification timestamp, project ID, percentage, repository URL, source origin, and reason.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run: `python -m pytest tests/test_openssf_evidence.py -q`
Expected: PASS.

### Task 2: Bounded Current/Legacy Collection

**Files:**
- Modify: `appguardrail_core/openssf_evidence.py`
- Test: `tests/test_openssf_evidence_transport.py`

**Interfaces:**
- Produces: `collect_openssf_evidence(repository_url, *, verified_at=None, opener=None, timeout=15.0)`.
- Consumes: the official current and legacy JSON endpoints only.

- [ ] **Step 1: Write failing transport-classification tests**

Cover current-origin success, current empty-result fallback to legacy, no legacy call after a current match, redirects, HTTP 401/403, HTTP 404, HTTP 429/5xx, invalid JSON, non-list JSON, timeout/network failure, response-size bounds, and deterministic verification timestamps.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/test_openssf_evidence_transport.py -q`
Expected: FAIL because the collector is absent.

- [ ] **Step 3: Implement fixed-origin collection**

Use a no-redirect opener, percent-encode the repository URL, require JSON payloads, bound timeout and body size, classify transport failures without response-body leakage, and fall back to the legacy origin only when the current origin returns a valid empty result.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `python -m pytest tests/test_openssf_evidence_transport.py -q`
Expected: PASS.

### Task 3: CLI And Offline Evidence Ingestion

**Files:**
- Modify: `scanner/cli/appguardrail.py`
- Test: `tests/test_openssf_evidence_cli.py`

**Interfaces:**
- Produces: `appguardrail openssf-evidence --repository-url URL [--source-json PATH] [--verified-at ISO] [--out PATH]`.
- Consumes: live official evidence or a saved exact-URL search JSON array.

- [ ] **Step 1: Write failing CLI tests**

Cover help text, offline source JSON, stdout output, file output, deterministic timestamp, invalid source JSON, missing required repository URL, and preservation of the `appguardrail.findings.v1` envelope.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/test_openssf_evidence_cli.py -q`
Expected: FAIL because the command is absent.

- [ ] **Step 3: Implement the command**

Offline mode must parse the saved response through the same pure parser as live mode. Output exactly one normalized finding in the standard findings envelope. Evidence-state outcomes return success; malformed local input and file I/O errors return a clear non-zero CLI result.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `python -m pytest tests/test_openssf_evidence_cli.py -q`
Expected: PASS.

### Task 4: Buyer-Diligence Report Integration

**Files:**
- Modify: `appguardrail_core/reports.py`
- Test: `tests/test_openssf_evidence_report.py`

**Interfaces:**
- Consumes: normalized findings whose rule ID is `openssf-best-practices-evidence`.
- Produces: a dedicated `OpenSSF Best Practices Evidence` section in buyer-diligence reports.

- [ ] **Step 1: Write failing report tests**

Cover passing/silver/gold/in-progress rows, unavailable/malformed/permission-limited wording, evidence links, deterministic timestamps, Markdown-safe values, multiple repositories, and the explicit statement that no evidence record was supplied when absent.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/test_openssf_evidence_report.py -q`
Expected: FAIL because the report section is absent.

- [ ] **Step 3: Render the evidence section**

Insert the section after scope/evidence handling and before the findings summary. Never turn unavailable evidence into a registration claim. Reuse existing Markdown sanitization helpers for every externally controlled value.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `python -m pytest tests/test_openssf_evidence_report.py -q`
Expected: PASS.

### Task 5: Documentation, Coverage, And Autonomous Handoff

**Files:**
- Create: `docs/openssf-best-practices-evidence.md`
- Create: `CHANGELOG.d/865-openssf-evidence.md`
- Modify: `.github/workflows/tests.yml`
- Modify: `scripts/ci/commercial_readiness_loop.py`
- Test: `tests/test_openssf_evidence_release_contract.py`

**Interfaces:**
- Produces: exact statement-coverage enforcement, operator documentation, release notes, and a bounded next-gap registry.

- [ ] **Step 1: Write failing release-contract tests**

Require documentation, changelog fragment, official endpoint/status language, the OpenSSF gap's removal from `COMMERCIAL_GAPS`, and the next `enterprise-retention-audit-policy` gap remaining first.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/test_openssf_evidence_release_contract.py -q`
Expected: FAIL until docs, changelog, workflow, and registry changes exist.

- [ ] **Step 3: Add exact coverage enforcement**

Use `scripts.ci.verify_module_coverage` against `appguardrail_core/openssf_evidence.py` and all OpenSSF-focused tests in the Python 3.13 CI job.

- [ ] **Step 4: Document operation and evidence semantics**

Document current/legacy origins, exact-URL lookup, state meanings, offline mode, attribution, rate-limit-friendly usage, report integration, and the distinction between unavailable evidence and proven non-registration.

- [ ] **Step 5: Advance the commercial-readiness registry**

Remove the completed OpenSSF gap and retain the enterprise retention/audit-policy gap as the next bounded buyer-visible slice.

- [ ] **Step 6: Run complete verification**

Run:
- `python -m pytest -q`
- `python -m scripts.ci.verify_module_coverage --module appguardrail_core/openssf_evidence.py --test tests/test_openssf_evidence.py --test tests/test_openssf_evidence_transport.py --test tests/test_openssf_evidence_cli.py --test tests/test_openssf_evidence_report.py --test tests/test_openssf_evidence_release_contract.py`
- `python -m compileall -q appguardrail_core scanner scripts tests`
- `git diff --check`

Expected: all commands pass, with exact unrounded 100% statement coverage for the new module.
