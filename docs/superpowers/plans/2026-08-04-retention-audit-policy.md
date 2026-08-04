# Tenant Retention And Audit Policy Implementation Plan

> **For agentic workers:** Use the Superpowers test-driven development, systematic debugging, and verification-before-completion workflows. Every phase is independently reviewable and must merge only after exact-head protection succeeds.

**Goal:** Give enterprise buyers tenant-scoped retention controls, deterministic purge evidence, and append-only tamper-evident auditability without retaining secrets or customer payloads in governance logs.

**Architecture:** Keep policy calculations and canonical audit hashing in dependency-free `appguardrail_core` modules. Place SQLite schema migration and transactional persistence behind a narrow adapter. Expose owner-only control-plane endpoints after storage behavior is proven. Compose only non-secret posture metadata into buyer and organization evidence outputs.

**Standards:** NIST SP 800-53 Rev. 5, NIST SP 800-92, ISO/IEC 27001:2022, and GDPR Articles 5 and 17. Material sources must remain in operator documentation using APA 7th style.

## Phase 1: dependency-free policy and audit core

**Files:**
- Create `appguardrail_core/audit_events.py`
- Create `appguardrail_core/retention_policy.py`
- Modify `appguardrail_core/__init__.py`
- Create `tests/test_audit_events.py`
- Create `tests/test_retention_policy.py`
- Create `tests/test_retention_audit_release_contract.py`
- Create `docs/retention-audit-policy.md`
- Create `CHANGELOG.d/871-retention-audit-core.md`
- Create `.github/workflows/retention-audit-coverage.yml`

**Deliverables:**
- frozen policy, preview, receipt, and audit-event models;
- bounded product defaults with explicit non-legal-advice wording;
- optimistic-concurrency policy updates;
- UTC cutoff calculations;
- hash-bound purge previews and stale checks;
- non-secret purge receipts;
- tenant-local canonical audit hash chains;
- secret/raw-evidence redaction; and
- exact 100% statement coverage for both production modules.

## Phase 2: descriptive SQLite schema migration

**Files:**
- Create a narrow retention/audit persistence adapter.
- Modify `appguardrail_core/controlplane.py` only after legacy behavior is characterized.
- Add migration and persistence tests using real SQLite files.

**Deliverables:**
- versioned migration table;
- safe transactional migration of nonconforming legacy object names such as `orgs`, `scans`, and `keys` to descriptive multiword snake_case names;
- new multiword tables, indexes, and triggers for retention policies, legal holds, audit events, purge previews, and purge receipts;
- append-only triggers on audit events;
- tenant-scoped uniqueness and foreign keys;
- migration idempotency, rollback, and mixed-schema failure tests; and
- backward-compatible data preservation.

## Phase 3: owner API and atomic purge execution

**Files:**
- Modify the control-plane store and HTTP handler.
- Add focused store, API, concurrency, crash, and tenant-isolation tests.

**Deliverables:**
- owner-only retention read/update endpoints;
- legal-hold create/release endpoints;
- purge preview and execute endpoints;
- optimistic revision handling;
- idempotent execution receipts;
- one transaction for deletion, receipt, and audit event;
- stale-preview rejection before deletion;
- request correlation and non-secret action summaries; and
- secure handling of backups and operational caveats in documentation.

## Phase 4: buyer-diligence and organization evidence

**Files:**
- Extend buyer-diligence and organization evidence renderers.
- Add package and installed-wheel smoke tests.
- Consolidate release notes into `CHANGELOG.md` only after release validation.

**Deliverables:**
- retention posture, policy revision, last purge receipt, legal-hold posture, and audit-chain verification status;
- no customer findings, snippets, credentials, or webhook secrets;
- standalone and MSA/naruon integration examples;
- package build, SBOM, provenance, migration, rollback, and operational recovery evidence; and
- a release decision based on current-head full validation.

**Issue closure:** Closes #871 only after Phase 4 is merged and the complete protected release candidate has been verified.
