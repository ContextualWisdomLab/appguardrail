# Retention Schema Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an atomic, idempotent SQLite migration from the embedded control plane's legacy one-word tables to descriptive canonical tables and add the persistence schema needed by tenant retention and tamper-evident audit workflows.

**Architecture:** Add one dependency-free `appguardrail_core.controlplane_schema` module that inspects and migrates a supplied `sqlite3.Connection`. Keep query/API adaptation out of this phase; the migrator preserves legacy columns while renaming tables, then adds retention and audit objects. Use real temporary SQLite files for rollback, foreign-key, append-only, and data-preservation tests.

**Tech Stack:** Python 3.11+, standard-library `sqlite3`, existing `scripts.ci.verify_module_coverage`, pytest, GitHub Actions.

## Global Constraints

- Target `develop` and keep the module independently importable by standalone AppGuardrail, organization services, and naruon.
- Use only multiword `snake_case` names for every new table, index, and trigger.
- Do not create legacy compatibility views.
- Do not enable `PRAGMA writable_schema`.
- Enable foreign-key enforcement before opening the migration transaction.
- Reject mixed, malformed, foreign-key-invalid, and future-version databases without partial mutation.
- Preserve tenant, scan, access-key, webhook, findings, and drift data exactly.
- Keep public functions, classes, and non-obvious behavior documented.
- Require exact unrounded 100% statement coverage for changed production modules.
- Keep APA 7th references in the design documentation.
- Do not close issue #871; owner APIs and purge execution remain Phase 3.

---

### Task 1: Schema inspection and failing migration contracts

**Files:**
- Create: `tests/test_controlplane_schema_migration.py`
- Create: `tests/test_controlplane_schema_failure_edges.py`

**Interfaces:**
- Consumes: `sqlite3.Connection`
- Produces test contracts for: `migrate_controlplane_schema(connection) -> SchemaMigrationResult`, `inspect_controlplane_schema(connection) -> SchemaInspection`

- [ ] **Step 1: Write the fresh-schema failing test**

Create an in-memory connection, call `migrate_controlplane_schema`, and assert the exact canonical table, index, and trigger names, `PRAGMA foreign_keys = 1`, and `PRAGMA user_version = 2`.

- [ ] **Step 2: Write the legacy-data preservation failing test**

Create the reviewed `orgs`, `scans`, `keys`, and `idx_scans_org` schema, insert a tenant, webhook URL, normalized findings JSON, drift count, role, label, and deterministic key hash, then assert migration preserves each value in `tenant_organizations`, `security_scans`, and `access_keys`.

- [ ] **Step 3: Write failure-edge tests**

Cover mixed legacy/canonical tables, a missing required legacy column, a future `user_version`, an open caller transaction, an injected mid-migration failure, and a foreign-key-invalid legacy row. Snapshot `sqlite_schema` and row data before each failure and assert they are unchanged afterward.

- [ ] **Step 4: Run tests and verify RED**

Run:

```bash
python -m pytest -q \
  tests/test_controlplane_schema_migration.py \
  tests/test_controlplane_schema_failure_edges.py
```

Expected: collection error because `appguardrail_core.controlplane_schema` does not exist.

- [ ] **Step 5: Commit the failing contracts**

```bash
git add tests/test_controlplane_schema_migration.py tests/test_controlplane_schema_failure_edges.py
git commit -m "test(schema): define atomic control-plane migration"
```

### Task 2: Atomic migration core

**Files:**
- Create: `appguardrail_core/controlplane_schema.py`
- Modify: `tests/test_controlplane_schema_migration.py`
- Modify: `tests/test_controlplane_schema_failure_edges.py`

**Interfaces:**
- Produces:
  - `CURRENT_SCHEMA_VERSION: int = 2`
  - `SchemaInspection`
  - `SchemaMigrationResult`
  - `inspect_controlplane_schema(connection: sqlite3.Connection) -> SchemaInspection`
  - `migrate_controlplane_schema(connection: sqlite3.Connection) -> SchemaMigrationResult`
- Consumes: a caller-owned `sqlite3.Connection` with no active transaction

- [ ] **Step 1: Implement deterministic schema inspection**

Read `sqlite_schema`, `PRAGMA table_info`, `PRAGMA foreign_keys`, and `PRAGMA user_version`. Return frozen sets and mappings without logging row contents.

- [ ] **Step 2: Validate migration preconditions**

Reject non-connections, active transactions, future versions, mixed legacy/canonical pairs, and legacy tables missing required columns. Enable foreign keys before `BEGIN IMMEDIATE` and confirm the pragma became active.

- [ ] **Step 3: Implement legacy renames and canonical index**

Within one transaction execute:

```sql
ALTER TABLE orgs RENAME TO tenant_organizations;
ALTER TABLE scans RENAME TO security_scans;
ALTER TABLE keys RENAME TO access_keys;
DROP INDEX IF EXISTS idx_scans_org;
CREATE INDEX security_scans_tenant_order_idx
  ON security_scans(org_id, id DESC);
```

Run only the statements required by the inspected state.

- [ ] **Step 4: Create governance persistence objects**

Create `schema_migrations`, `retention_policies`, `legal_holds`, `audit_events`, `audit_chain_checkpoints`, `purge_previews`, and `purge_receipts`, plus descriptive indexes. Store JSON metadata as canonical text fields and use tenant foreign keys.

- [ ] **Step 5: Install append-only audit triggers**

Create `audit_events_prevent_update` and `audit_events_prevent_delete` using `RAISE(ABORT, 'audit_events are append-only')`.

- [ ] **Step 6: Verify and commit atomically**

Insert migration version 2, set `PRAGMA user_version = 2`, run `PRAGMA foreign_key_check`, and commit only when the result is empty. Roll back every exception and re-raise one bounded `SchemaMigrationError` without customer row contents.

- [ ] **Step 7: Run focused tests and verify GREEN**

Run the Task 1 command. Expected: PASS.

- [ ] **Step 8: Commit the implementation**

```bash
git add appguardrail_core/controlplane_schema.py tests/test_controlplane_schema_*.py
git commit -m "feat(schema): add atomic retention migration"
```

### Task 3: Append-only, idempotency, and public API contracts

**Files:**
- Modify: `appguardrail_core/__init__.py`
- Create: `tests/test_controlplane_schema_contract.py`
- Create: `docs/controlplane-schema-migration.md`
- Create: `CHANGELOG.d/871-retention-schema-migration.md`

**Interfaces:**
- Public exports: `CURRENT_SCHEMA_VERSION`, `SchemaInspection`, `SchemaMigrationResult`, `inspect_controlplane_schema`, `migrate_controlplane_schema`

- [ ] **Step 1: Write failing public API and idempotency tests**

Assert public exports, a no-op second migration result, append-only trigger failures for `UPDATE` and `DELETE`, and absence of `orgs`, `scans`, `keys`, `idx_scans_org`, or any one-word newly introduced table/index/trigger.

- [ ] **Step 2: Write installed documentation contracts**

Require migration, rollback, backup, external checkpoint, no-compatibility-view, and Phase 3 integration limitations, plus APA 7th SQLite references.

- [ ] **Step 3: Export the public API and write operator docs**

Add package exports without importing the scanner CLI. Document that current control-plane queries are adapted in Phase 3 and must not open a legacy database after standalone migration until that phase is deployed.

- [ ] **Step 4: Run focused tests**

```bash
python -m pytest -q \
  tests/test_controlplane_schema_migration.py \
  tests/test_controlplane_schema_failure_edges.py \
  tests/test_controlplane_schema_contract.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add appguardrail_core/__init__.py docs/controlplane-schema-migration.md \
  CHANGELOG.d/871-retention-schema-migration.md tests/test_controlplane_schema_contract.py
git commit -m "docs(schema): publish migration contract"
```

### Task 4: Exact coverage and protected PR

**Files:**
- Create: `.github/workflows/controlplane-schema-coverage.yml`
- Create: `tests/test_controlplane_schema_coverage_edges.py`
- Create: `tests/test_controlplane_schema_release_contract.py`

**Interfaces:**
- Consumes all Phase 2 modules and tests
- Produces exact-head CI evidence and bounded Phase 3 handoff

- [ ] **Step 1: Write uncovered-edge tests**

Cover every bounded error branch, empty fresh inspection, legacy-only inspection, canonical-only inspection, migration result serialization, trigger metadata, and rollback path.

- [ ] **Step 2: Add least-privilege coverage workflow**

Use `contents: read`, a PR/ref concurrency group with `cancel-in-progress: true`, Python 3.13, hash-locked dependencies, focused pytest, and:

```bash
python -m scripts.ci.verify_module_coverage \
  --module appguardrail_core/controlplane_schema.py \
  --test tests/test_controlplane_schema_migration.py \
  --test tests/test_controlplane_schema_failure_edges.py \
  --test tests/test_controlplane_schema_contract.py \
  --test tests/test_controlplane_schema_coverage_edges.py \
  --test tests/test_controlplane_schema_release_contract.py
```

- [ ] **Step 3: Run full validation**

```bash
python -m pytest -q
python -m scripts.ci.verify_module_coverage --module appguardrail_core/controlplane_schema.py \
  --test tests/test_controlplane_schema_migration.py \
  --test tests/test_controlplane_schema_failure_edges.py \
  --test tests/test_controlplane_schema_contract.py \
  --test tests/test_controlplane_schema_coverage_edges.py \
  --test tests/test_controlplane_schema_release_contract.py
python -m compileall -q appguardrail_core scanner scripts tests
git diff --check
```

Expected: all commands pass and the migration module reports exact 100% statement coverage.

- [ ] **Step 4: Open a draft PR**

Target `develop`, reference #871 without closing it, and state that Phase 3 must atomically adapt the existing store/API before invoking the standalone migration in production.

- [ ] **Step 5: Address every review and merge only exact-head success**

Resolve actionable review threads, rerun current-head checks, require CodeRabbit/OpenCode or repository-equivalent gates, and squash merge only when protected rules pass.
