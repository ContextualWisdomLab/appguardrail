"""Public and release-facing contracts for the control-plane schema migrator."""

from __future__ import annotations

import sqlite3

import pytest

import appguardrail_core
from appguardrail_core.controlplane_schema import (
    CANONICAL_INDEX_NAMES,
    CANONICAL_TABLE_NAMES,
    CANONICAL_TRIGGER_NAMES,
    CURRENT_SCHEMA_VERSION,
    SchemaMigrationError,
    inspect_controlplane_schema,
    migrate_controlplane_schema,
)


LEGACY_OBJECT_NAMES = {"orgs", "scans", "keys", "idx_scans_org"}


def test_schema_migration_is_published_from_reusable_core() -> None:
    """Standalone services and naruon modules use public package exports."""
    assert appguardrail_core.CURRENT_SCHEMA_VERSION == CURRENT_SCHEMA_VERSION
    assert appguardrail_core.inspect_controlplane_schema is inspect_controlplane_schema
    assert appguardrail_core.migrate_controlplane_schema is migrate_controlplane_schema
    assert appguardrail_core.SchemaMigrationError is SchemaMigrationError


def test_canonical_schema_objects_are_descriptive_multiword_names() -> None:
    """Tables, indexes, and triggers satisfy the multiword naming contract."""
    canonical_names = (
        CANONICAL_TABLE_NAMES | CANONICAL_INDEX_NAMES | CANONICAL_TRIGGER_NAMES
    )

    assert canonical_names
    assert not canonical_names & LEGACY_OBJECT_NAMES
    assert all("_" in object_name for object_name in canonical_names)
    assert all(object_name == object_name.lower() for object_name in canonical_names)


def test_fresh_database_migration_is_inspectable_and_idempotent() -> None:
    """A new database gets one complete schema and a stable second-run result."""
    connection = sqlite3.connect(":memory:")

    first = migrate_controlplane_schema(connection)
    inspection = inspect_controlplane_schema(connection)
    second = migrate_controlplane_schema(connection)

    assert first.previous_version == 0
    assert first.current_version == CURRENT_SCHEMA_VERSION
    assert first.changed is True
    assert first.migrated_legacy_schema is False
    assert inspection.foreign_keys_enabled is True
    assert inspection.table_names == CANONICAL_TABLE_NAMES
    assert CANONICAL_INDEX_NAMES <= inspection.index_names
    assert inspection.trigger_names == CANONICAL_TRIGGER_NAMES
    assert second.changed is False
    assert second.previous_version == CURRENT_SCHEMA_VERSION
    assert second.current_version == CURRENT_SCHEMA_VERSION

    with pytest.raises(TypeError):
        inspection.table_columns["unexpected_table"] = frozenset()


def test_current_version_with_missing_object_fails_closed() -> None:
    """Version metadata cannot hide a deleted required migration object."""
    connection = sqlite3.connect(":memory:")
    migrate_controlplane_schema(connection)
    connection.execute("DROP INDEX security_scans_tenant_order_idx")

    with pytest.raises(SchemaMigrationError, match="incomplete"):
        migrate_controlplane_schema(connection)


def test_current_version_rejects_legacy_index_residue() -> None:
    """A legacy index added after migration is treated as schema tampering."""
    connection = sqlite3.connect(":memory:")
    migrate_controlplane_schema(connection)
    connection.execute(
        "CREATE INDEX idx_scans_org ON security_scans(org_id, id DESC)"
    )

    with pytest.raises(SchemaMigrationError, match="legacy objects"):
        migrate_controlplane_schema(connection)
