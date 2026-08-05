# Control-plane schema migration

AppGuardrail's embedded SQLite control plane originally used the one-word table names `orgs`, `scans`, and `keys`, plus the index `idx_scans_org`. The version-two migration replaces those objects with descriptive multiword `snake_case` names and installs the persistence boundary required by retention policy, legal hold, purge preview, purge receipt, and tamper-evident audit features.

This module is intentionally independent of the HTTP control plane. Standalone AppGuardrail, organization services, and naruon integrations can inspect or migrate a caller-owned `sqlite3.Connection` without importing the scanner CLI.

## Supported entry points

```python
import sqlite3

from appguardrail_core import (
    inspect_controlplane_schema,
    migrate_controlplane_schema,
)

connection = sqlite3.connect("control-plane.db")
inspection = inspect_controlplane_schema(connection)
result = migrate_controlplane_schema(connection)
```

The caller owns the connection and must close it. The migration refuses to run inside an active caller transaction.

## Backup rehearsal before migration

Create and verify a point-in-time SQLite backup before applying the migration to a durable database. Python's `sqlite3.Connection.backup()` copies a live database through SQLite's backup API without selecting customer rows into application logs.

```python
import sqlite3

source = sqlite3.connect("control-plane.db")
target = sqlite3.connect("control-plane.pre-v2.db")
with target:
    source.backup(target)

assert target.execute("PRAGMA integrity_check").fetchone() == ("ok",)
source.close()
target.close()
```

Keep the backup outside the deployment's writable database directory, record its content hash and access controls, and rehearse restore in an isolated environment. A successful backup is not a substitute for testing the migrated application against a copy of production-shaped data.

## Canonical database objects

### Base tables

- `tenant_organizations`
- `security_scans`
- `access_keys`

### Governance tables

- `schema_migrations`
- `retention_policies`
- `legal_holds`
- `audit_events`
- `audit_chain_checkpoints`
- `purge_previews`
- `purge_receipts`

### Indexes

- `security_scans_tenant_order_idx`
- `audit_events_tenant_sequence_idx`
- `legal_holds_tenant_state_idx`
- `purge_receipts_tenant_execution_idx`

### Triggers

- `audit_events_prevent_update`
- `audit_events_prevent_delete`

The migration does not create legacy compatibility views. Application code must move to the canonical names before production startup invokes the migration.

## Safety properties

The migrator applies the following fail-closed sequence:

1. Verify that the input is a live `sqlite3.Connection`.
2. Read only SQLite schema metadata; no tenant row, API-key hash, webhook URL, finding, or audit payload is logged.
3. Reject future schema versions, partial legacy schemas, partial canonical schemas, and mixed legacy/canonical states.
4. Enable and verify per-connection foreign-key enforcement before the migration transaction.
5. Acquire a write reservation with `BEGIN IMMEDIATE`.
6. Rename validated legacy tables or create the canonical base schema for a fresh database.
7. Create governance tables, indexes, and append-only audit triggers.
8. Record the migration and set `PRAGMA user_version = 2`.
9. Run `PRAGMA foreign_key_check` before commit.
10. Commit every schema change together, or roll back the complete transaction on any error.

SQLite updates indexes, triggers, views, and foreign-key references during supported table renames on current SQLite versions. AppGuardrail nevertheless enables foreign keys before migration and explicitly verifies referential integrity before commit. The implementation does not use `PRAGMA writable_schema`, because bypassing schema parsing would weaken fail-closed validation (SQLite Consortium, 2026a, 2026b).

Python's `sqlite3.Connection.in_transaction` is used to reject nested caller transactions. AppGuardrail controls its own `BEGIN IMMEDIATE`, `commit()`, and `rollback()` boundary explicitly (Python Software Foundation, 2026).

## Idempotence and failure semantics

Running the migration again on a complete version-two database returns `changed=False` after validating all required objects. A version-two database missing a required table, index, or trigger is rejected rather than silently repaired, because silent repair could conceal manual tampering or an interrupted out-of-band change.

A failed migration raises `SchemaMigrationError` with a bounded operational category. It does not include customer rows, key hashes, findings, webhook targets, or SQL payload content.

## Phase boundary

This slice preserves the reviewed legacy column contract while replacing table, index, and trigger names. The following control-plane integration slice must:

- update every query in `appguardrail_core.controlplane` to canonical object names;
- migrate remaining one-word column names to descriptive multiword names where compatibility permits;
- invoke the migrator during controlled startup;
- verify old-database upgrade, fresh-database bootstrap, rollback, backup, and restore behavior through the public API;
- provide an operator backup and recovery runbook before release.

Until that integration is merged, operators should invoke this standalone module only in an explicit migration rehearsal or controlled maintenance procedure.

## References

Python Software Foundation. (2026). *sqlite3—DB-API 2.0 interface for SQLite databases* (Python 3.13 documentation). https://docs.python.org/3.13/library/sqlite3.html

SQLite Consortium. (2026a). *ALTER TABLE*. SQLite. https://sqlite.org/lang_altertable.html

SQLite Consortium. (2026b). *PRAGMA statements*. SQLite. https://sqlite.org/pragma.html

SQLite Consortium. (2026c). *Transaction*. SQLite. https://sqlite.org/lang_transaction.html
