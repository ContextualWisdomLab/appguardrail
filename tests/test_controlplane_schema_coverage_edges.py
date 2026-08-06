"""Coverage and defensive-edge tests for SQLite schema migration."""

from __future__ import annotations

import sqlite3

import pytest

from appguardrail_core import controlplane_schema as schema


class InspectionFailureConnection(sqlite3.Connection):
    """Raise a bounded database error at the schema-catalog boundary."""

    def execute(self, sql: str, parameters=(), /):  # type: ignore[override]
        """Fail only the catalog query while allowing liveness pragmas."""
        if sql.startswith("SELECT type, name FROM sqlite_schema"):
            raise sqlite3.DatabaseError("catalog unavailable")
        return super().execute(sql, parameters)


class ForeignKeyDisabledConnection(sqlite3.Connection):
    """Simulate a SQLite connection unable to enable foreign keys."""

    def execute(self, sql: str, parameters=(), /):  # type: ignore[override]
        """Ignore the enable request so the migrator must fail closed."""
        if sql == "PRAGMA foreign_keys = ON":
            return super().execute("PRAGMA foreign_keys = OFF")
        return super().execute(sql, parameters)


class ProgrammingFailureConnection(sqlite3.Connection):
    """Pass the liveness probe and then fail schema inspection as closed."""

    def execute(self, sql: str, parameters=(), /):  # type: ignore[override]
        """Raise the driver error after the initial live-connection probe."""
        if sql == "PRAGMA user_version":
            raise sqlite3.ProgrammingError("closed after probe")
        return super().execute(sql, parameters)


class TransactionStateFailureConnection(sqlite3.Connection):
    """Expose a connection whose transaction-state read fails defensively."""

    @property
    def in_transaction(self) -> bool:  # type: ignore[override]
        """Raise the driver error covered by the migration boundary."""
        raise sqlite3.ProgrammingError("transaction state unavailable")


def test_non_connection_is_rejected() -> None:
    """Public entry points reject objects that cannot provide SQLite semantics."""
    with pytest.raises(ValueError, match=r"sqlite3\.Connection"):
        schema.inspect_controlplane_schema(object())  # type: ignore[arg-type]


def test_closed_connection_has_bounded_error() -> None:
    """A closed connection does not leak the sqlite driver exception text."""
    connection = sqlite3.connect(":memory:")
    connection.close()

    with pytest.raises(schema.SchemaMigrationError, match="closed connection"):
        schema.migrate_controlplane_schema(connection)


def test_connection_closed_after_probe_has_bounded_inspection_error() -> None:
    """A post-probe ProgrammingError remains in the closed-connection category."""
    connection = sqlite3.connect(":memory:", factory=ProgrammingFailureConnection)

    with pytest.raises(schema.SchemaMigrationError, match="closed connection"):
        schema.inspect_controlplane_schema(connection)


def test_transaction_state_programming_error_is_bounded() -> None:
    """Migration bounds a driver failure while reading transaction state."""
    connection = sqlite3.connect(
        ":memory:", factory=TransactionStateFailureConnection
    )

    with pytest.raises(schema.SchemaMigrationError, match="closed connection"):
        schema.migrate_controlplane_schema(connection)


def test_schema_catalog_database_error_is_bounded() -> None:
    """Catalog failures become one stable operator-facing error category."""
    connection = sqlite3.connect(":memory:", factory=InspectionFailureConnection)

    with pytest.raises(schema.SchemaMigrationError, match="inspection failed"):
        schema.inspect_controlplane_schema(connection)


def test_incomplete_legacy_schema_is_rejected_before_transaction() -> None:
    """One legacy table cannot be guessed into a valid historical schema."""
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE orgs(id INTEGER PRIMARY KEY)")

    with pytest.raises(schema.SchemaMigrationError, match="incomplete legacy"):
        schema.migrate_controlplane_schema(connection)

    assert connection.in_transaction is False
    assert schema.inspect_controlplane_schema(connection).table_names == frozenset(
        {"orgs"}
    )


def test_incomplete_canonical_schema_is_rejected_before_transaction() -> None:
    """A partial canonical base cannot be silently treated as a fresh database."""
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE tenant_organizations(id INTEGER PRIMARY KEY)"
    )

    with pytest.raises(schema.SchemaMigrationError, match="incomplete canonical"):
        schema.migrate_controlplane_schema(connection)


def test_canonical_base_without_version_is_completed() -> None:
    """A reviewed canonical base receives governance objects without row copying."""
    connection = sqlite3.connect(":memory:")
    schema._create_base_tables(connection)
    connection.commit()

    result = schema.migrate_controlplane_schema(connection)

    assert result.changed is True
    assert result.migrated_legacy_schema is False
    assert schema.inspect_controlplane_schema(connection).table_names == (
        schema.CANONICAL_TABLE_NAMES
    )


def test_foreign_key_enablement_failure_stops_before_begin() -> None:
    """Migration cannot continue when the connection ignores FK enforcement."""
    connection = sqlite3.connect(":memory:", factory=ForeignKeyDisabledConnection)

    with pytest.raises(schema.SchemaMigrationError, match="could not be enabled"):
        schema.migrate_controlplane_schema(connection)

    assert connection.in_transaction is False
    assert schema.inspect_controlplane_schema(connection).table_names == frozenset()


def test_identifier_quoting_escapes_embedded_quotes() -> None:
    """Schema-catalog identifiers are quoted defensively when needed."""
    assert schema._quoted_identifier('odd"table') == '"odd""table"'
