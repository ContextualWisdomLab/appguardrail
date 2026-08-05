"""Fail-closed and rollback contracts for control-plane schema migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from appguardrail_core.controlplane_schema import (
    CURRENT_SCHEMA_VERSION,
    SchemaMigrationError,
    inspect_controlplane_schema,
    migrate_controlplane_schema,
)
from tests.test_controlplane_schema_migration import LEGACY_SCHEMA


def _connection(path: Path | str = ":memory:") -> sqlite3.Connection:
    """Return one row-enabled SQLite connection for failure tests."""
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def _schema_snapshot(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    """Return deterministic schema metadata without reading customer row values."""
    return tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        )
    )


def test_mixed_legacy_and_canonical_tables_fail_without_partial_mutation() -> None:
    """Coexisting old and new names are ambiguous and never auto-merged."""
    connection = _connection()
    connection.executescript(LEGACY_SCHEMA)
    connection.execute(
        "CREATE TABLE tenant_organizations(id INTEGER PRIMARY KEY, name TEXT)"
    )
    connection.commit()
    before = _schema_snapshot(connection)

    with pytest.raises(SchemaMigrationError, match="mixed schema"):
        migrate_controlplane_schema(connection)

    assert _schema_snapshot(connection) == before
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0


def test_malformed_legacy_columns_fail_before_any_table_is_renamed() -> None:
    """Missing legacy data columns stop migration before its first DDL statement."""
    connection = _connection()
    connection.executescript(
        """
        CREATE TABLE orgs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL REFERENCES orgs(id),
            created_at TEXT NOT NULL,
            repo TEXT,
            commit_sha TEXT,
            total INTEGER NOT NULL,
            deploy_blocking INTEGER NOT NULL,
            severity_counts TEXT NOT NULL,
            new_blocking INTEGER NOT NULL DEFAULT 0,
            findings TEXT NOT NULL
        );
        CREATE TABLE keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL REFERENCES orgs(id),
            key_hash TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            label TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    connection.commit()
    before = _schema_snapshot(connection)

    with pytest.raises(SchemaMigrationError, match="api_key_hash"):
        migrate_controlplane_schema(connection)

    assert _schema_snapshot(connection) == before
    assert "orgs" in inspect_controlplane_schema(connection).table_names


def test_future_schema_version_is_rejected_without_downgrade() -> None:
    """An older binary cannot reinterpret or overwrite a newer database schema."""
    connection = _connection()
    connection.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION + 1}")
    before = _schema_snapshot(connection)

    with pytest.raises(SchemaMigrationError, match="newer schema version"):
        migrate_controlplane_schema(connection)

    assert _schema_snapshot(connection) == before
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_active_caller_transaction_is_rejected_without_committing_it() -> None:
    """The migrator cannot steal transaction ownership from its caller."""
    connection = _connection()
    connection.execute("CREATE TABLE caller_state(state_id INTEGER PRIMARY KEY)")
    connection.execute("INSERT INTO caller_state(state_id) VALUES (1)")
    assert connection.in_transaction is True

    with pytest.raises(SchemaMigrationError, match="active transaction"):
        migrate_controlplane_schema(connection)

    assert connection.in_transaction is True
    connection.rollback()
    assert connection.execute("SELECT COUNT(*) FROM caller_state").fetchone()[0] == 0


def test_injected_mid_migration_failure_rolls_back_renames_and_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fault after legacy renames leaves the original schema fully usable."""
    connection = _connection()
    connection.executescript(LEGACY_SCHEMA)
    connection.execute(
        "INSERT INTO orgs(name, api_key_hash, created_at) "
        "VALUES ('Acme', 'bootstrap-hash', '2026-08-04T12:00:00Z')"
    )
    connection.commit()
    before = _schema_snapshot(connection)

    def fail_governance_schema(_connection: sqlite3.Connection) -> None:
        """Raise at the documented injection boundary after legacy renames."""
        raise RuntimeError("injected phase-two failure")

    monkeypatch.setattr(
        "appguardrail_core.controlplane_schema._create_governance_objects",
        fail_governance_schema,
    )

    with pytest.raises(SchemaMigrationError, match="migration failed"):
        migrate_controlplane_schema(connection)

    assert _schema_snapshot(connection) == before
    assert connection.execute("SELECT name FROM orgs WHERE id = 1").fetchone()[0] == "Acme"
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0


def test_foreign_key_violation_rolls_back_complete_migration() -> None:
    """Orphaned legacy rows cannot be hidden behind a successful schema upgrade."""
    connection = _connection()
    connection.executescript(LEGACY_SCHEMA)
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute(
        "INSERT INTO scans(org_id, created_at, repo, commit_sha, total, "
        "deploy_blocking, severity_counts, new_blocking, findings) "
        "VALUES (99, '2026-08-04T12:05:00Z', 'acme/repo', 'deadbeef', 1, 1, "
        "'{\"CRITICAL\":0,\"HIGH\":1,\"WARNING\":0,\"INFO\":0}', 1, '[]')"
    )
    connection.commit()
    before = _schema_snapshot(connection)

    with pytest.raises(SchemaMigrationError, match="foreign key check"):
        migrate_controlplane_schema(connection)

    assert _schema_snapshot(connection) == before
    assert connection.execute("SELECT org_id FROM scans").fetchone()[0] == 99
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0


def test_non_connection_and_closed_connection_are_rejected_cleanly() -> None:
    """Public migration boundaries reject unsupported or unusable connection objects."""
    with pytest.raises(ValueError, match=r"sqlite3\.Connection"):
        migrate_controlplane_schema(object())

    connection = _connection()
    connection.close()
    with pytest.raises(SchemaMigrationError, match="closed connection"):
        migrate_controlplane_schema(connection)



class ConcurrentCompletionConnection(sqlite3.Connection):
    """Simulate another process completing migration before this writer locks."""

    completed_competing_migration = False

    def execute(self, sql: str, parameters=(), /):  # type: ignore[override]
        """Install version two immediately before the first write reservation."""
        if sql == "BEGIN IMMEDIATE" and not self.completed_competing_migration:
            from appguardrail_core import controlplane_schema as schema

            schema._create_base_tables(self)
            schema._create_governance_objects(self)
            super().execute(
                "INSERT INTO schema_migrations(schema_version, migration_name) "
                "VALUES (?, ?)",
                (schema.CURRENT_SCHEMA_VERSION, schema.MIGRATION_NAME),
            )
            super().execute("PRAGMA user_version = 2")
            self.commit()
            self.completed_competing_migration = True
        return super().execute(sql, parameters)


def test_post_lock_schema_snapshot_handles_concurrent_completion() -> None:
    """A competing successful migrator turns this invocation into an idempotent no-op."""
    connection = sqlite3.connect(
        ":memory:", factory=ConcurrentCompletionConnection
    )

    result = migrate_controlplane_schema(connection)

    assert result.changed is False
    assert result.previous_version == CURRENT_SCHEMA_VERSION
    assert result.current_version == CURRENT_SCHEMA_VERSION
    assert connection.in_transaction is False
    assert inspect_controlplane_schema(connection).user_version == CURRENT_SCHEMA_VERSION
