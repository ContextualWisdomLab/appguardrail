# Retention Schema Migration Design

## Goal

Add a dependency-free SQLite schema migrator that converts the embedded control plane's legacy one-word table names into descriptive multiword `snake_case` objects, preserves existing tenant, scan, and access-key data, and installs the persistence objects required by the retention and tamper-evident audit core.

This is Phase 2 of issue #871. It deliberately stops before owner HTTP endpoints and purge execution.

## Existing schema evidence

The reviewed `develop` schema currently creates `orgs`, `scans`, and `keys`, plus `idx_scans_org`. Existing databases may contain live tenant identifiers, deterministic API-key hashes, webhook configuration, normalized findings payloads, drift counts, and role-scoped access keys. Migration must preserve all of them exactly.

SQLite foreign-key enforcement is disabled by default unless explicitly enabled on each connection. `PRAGMA foreign_keys` cannot be changed inside an active transaction, so the migrator enables enforcement before beginning its atomic migration. SQLite's modern `ALTER TABLE RENAME TO` updates dependent foreign-key references, triggers, and views unless legacy alter-table behavior is enabled; the migrator nevertheless validates schema shape and runs `PRAGMA foreign_key_check` before commit.

## Canonical object names

### Existing data, migrated

- `orgs` → `tenant_organizations`
- `scans` → `security_scans`
- `keys` → `access_keys`
- `idx_scans_org` → `security_scans_tenant_order_idx`

The first migration preserves legacy column names so Phase 2 remains bounded and does not couple schema migration to the full control-plane query rewrite. Phase 3 will migrate columns transactionally while adapting the owner API and persistence methods. No compatibility views with one-word names are created.

### New retention and audit objects

- `schema_migrations`
- `retention_policies`
- `legal_holds`
- `audit_events`
- `audit_chain_checkpoints`
- `purge_previews`
- `purge_receipts`
- `audit_events_tenant_sequence_idx`
- `legal_holds_tenant_state_idx`
- `purge_receipts_tenant_execution_idx`
- `audit_events_prevent_update`
- `audit_events_prevent_delete`

Every new table, index, and trigger name contains at least two words and uses `snake_case`.

## Atomic migration algorithm

1. Require a `sqlite3.Connection` with no pending transaction.
2. Enable `PRAGMA foreign_keys = ON` before `BEGIN IMMEDIATE`.
3. Read `sqlite_schema`, `PRAGMA table_info`, and `PRAGMA user_version`.
4. Fail closed if legacy and canonical versions of the same object coexist.
5. Validate required legacy columns before renaming any table.
6. Rename legacy tables in dependency order: organization, scans, access keys.
7. Drop the legacy index and create the canonical index.
8. Create retention, legal-hold, audit, checkpoint, preview, and receipt objects.
9. Install append-only update/delete triggers for `audit_events`.
10. Insert one `schema_migrations` record and set `PRAGMA user_version`.
11. Run `PRAGMA foreign_key_check` and fail if any row is returned.
12. Commit. Any exception rolls the complete migration back.

A fresh database receives canonical objects directly. Re-running the migrator is idempotent. A mixed, malformed, future-version, or foreign-key-invalid database is rejected without partial mutation.

## Trust boundaries

- Migration never logs API-key hashes, findings JSON, webhook URLs, or customer evidence.
- The migrator does not enable `PRAGMA writable_schema`.
- Audit events are append-only at the database layer through update/delete triggers.
- Hash-chain checkpoints are stored separately from mutable event rows, but an independently controlled external checkpoint remains necessary against full-database replacement.
- Purge previews and receipts store counts and hashes, not deleted row bodies.
- Product defaults remain non-legal-advice values from the Phase 1 core.

## Tests

Tests use real temporary SQLite files and cover:

- fresh canonical schema creation;
- legacy schema migration with real tenant, scan, webhook, role, and key-hash rows;
- foreign-key enforcement and `foreign_key_check`;
- idempotent second execution;
- mixed-schema fail-closed behavior;
- malformed legacy-column fail-closed behavior;
- future `user_version` rejection;
- rollback after an injected migration failure;
- append-only trigger enforcement;
- multiword object naming; and
- public module, docs, changelog, plan, and exact 100% coverage contracts.

## References (APA 7th)

SQLite Consortium. (n.d.). *ALTER TABLE*. SQLite Documentation. Retrieved August 4, 2026, from https://www.sqlite.org/lang_altertable.html

SQLite Consortium. (n.d.). *Pragma statements*. SQLite Documentation. Retrieved August 4, 2026, from https://www.sqlite.org/pragma.html

SQLite Consortium. (n.d.). *Transaction*. SQLite Documentation. Retrieved August 4, 2026, from https://www.sqlite.org/lang_transaction.html
