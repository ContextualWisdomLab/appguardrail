# Control-plane schema migration

AppGuardrail's embedded SQLite control plane originally used the one-word table names `orgs`, `scans`, and `keys`, plus the index `idx_scans_org`. The version-two migration replaces those objects with descriptive multiword `snake_case` table/index names and installs the persistence boundary required by retention policy, legal hold, purge preview, purge receipt, and tamper-evident audit features.

The migration module remains independent of the HTTP control plane. Standalone AppGuardrail, organization services, and naruon integrations can inspect or migrate a caller-owned `sqlite3.Connection` without importing the scanner CLI. The AppGuardrail runtime now also invokes the same migration boundary whenever `appguardrail_core.controlplane.connect()` or `make_control_plane_server()` opens its database, so the shipped runtime and the standalone migration contract use one schema authority.

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

For normal AppGuardrail runtime use, open through the control-plane API instead:

```python
from appguardrail_core.controlplane import connect

connection = connect("control-plane.db")
```

That runtime entry point enables canonical schema migration before returning the connection. If migration is ambiguous or invalid, startup fails closed and the newly opened connection is closed rather than serving requests against a mixed or partial schema.

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

Because current AppGuardrail runtime startup invokes migration automatically, operators upgrading a durable pre-v2 store must complete the backup/rehearsal step **before starting the upgraded control plane**. Rollback means stopping the upgraded process, retaining the failed/migrated database as evidence, restoring the verified pre-v2 backup to an isolated path, validating integrity, and only then deciding whether to restart a compatible build. Do not reverse schema changes manually with `PRAGMA writable_schema`.

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

The migration does not create legacy compatibility views. Runtime queries use the canonical table names directly after the migration succeeds.

## Safety properties

The migrator applies the following fail-closed sequence:

1. Verify that the input is a live `sqlite3.Connection`.
2. Read only SQLite schema metadata; no tenant row, API-key hash, webhook URL, finding, or audit payload is logged.
3. Reject future schema versions, partial legacy schemas, partial canonical schemas, and mixed legacy/canonical states.
4. Enable and verify per-connection foreign-key enforcement before the migration transaction.
5. Acquire a write reservation with `BEGIN IMMEDIATE`.
6. Reinspect and classify the schema while holding the write reservation so concurrent migrators become an idempotent no-op.
7. Rename validated legacy tables or create the canonical base schema for a fresh database.
8. Create governance tables, indexes, and append-only audit triggers.
9. Record the migration and set `PRAGMA user_version = 2`.
10. Run `PRAGMA foreign_key_check` before commit.
11. Commit every schema change together, or roll back the complete transaction on any error.

The post-lock inspection is the authoritative schema snapshot. A process that waited while another process completed the same migration observes version two after acquiring its own reservation, validates the complete canonical schema, rolls back its read-only transaction, and returns `changed=False` instead of attempting duplicate DDL.

SQLite updates indexes, triggers, views, and foreign-key references during supported table renames on current SQLite versions. AppGuardrail nevertheless enables foreign keys before migration and explicitly verifies referential integrity before commit. The implementation does not use `PRAGMA writable_schema`, because bypassing schema parsing would weaken fail-closed validation (SQLite Consortium, 2026a, 2026b).

Python's `sqlite3.Connection.in_transaction` is used to reject nested caller transactions. AppGuardrail controls its own `BEGIN IMMEDIATE`, `commit()`, and `rollback()` boundary explicitly (Python Software Foundation, 2026).

Audit events reference `tenant_organizations` with `ON DELETE RESTRICT` and remain protected by update/delete triggers. Tenant deletion and ordinary retention purges therefore cannot erase audit evidence. A future privileged audit-expiration mechanism must define a separately reviewed authorization, checkpoint, receipt, and chain-resealing contract before it can delete any audit row.

## Idempotence and failure semantics

Running the migration again on a complete version-two database returns `changed=False` after validating all required objects. A version-two database missing a required table, index, or trigger is rejected rather than silently repaired, because silent repair could conceal manual tampering or an interrupted out-of-band change.

A failed migration raises `SchemaMigrationError` with a bounded operational category. It does not include customer rows, key hashes, findings, webhook targets, or SQL payload content. Runtime startup propagates that failure after closing the connection; it does not silently create legacy tables or continue with an incomplete schema.

## Current phase boundary

The runtime now reads and writes the version-two canonical **table** names and invokes the migration during controlled startup. This removes the shipped dependency on the legacy table bootstrap while preserving the reviewed row/column contract and data values.

Issue #871 remains open. Subsequent independently reviewed slices still need to:

- migrate remaining one-word column names to descriptive multiword names where compatibility permits, with a versioned migration and rollback evidence;
- add owner-only retention-policy and legal-hold HTTP mutation APIs;
- add deterministic purge preview/execution persistence with idempotency, stale-preview rejection, legal-hold exclusion, and atomic audit receipt creation;
- expose non-secret retention/audit posture in buyer-diligence evidence;
- verify backup/restore and live upgrade behavior against production-shaped databases before release.

Do not represent the presence of the version-two schema alone as retention-policy enforcement or immutable-storage certification. Hash chaining and append-only database triggers are evidence controls with documented trust boundaries, not a certification claim.

## References

Python Software Foundation. (2026). *sqlite3—DB-API 2.0 interface for SQLite databases* (Python 3.13 documentation). https://docs.python.org/3.13/library/sqlite3.html

SQLite Consortium. (2026a). *ALTER TABLE*. SQLite. https://sqlite.org/lang_altertable.html

SQLite Consortium. (2026b). *PRAGMA statements*. SQLite. https://sqlite.org/pragma.html

SQLite Consortium. (2026c). *Transaction*. SQLite. https://sqlite.org/lang_transaction.html