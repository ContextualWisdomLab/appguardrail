"""Inspect and atomically migrate AppGuardrail's embedded SQLite schema.

The module is intentionally dependency-free so standalone AppGuardrail,
organization services, and naruon integrations can share the same migration
boundary. It preserves shipped legacy rows, installs retention and tamper-
evident audit persistence objects, and converges organization-owned database
columns on semantically specific bounded-context names.

The caller retains ownership of the supplied :class:`sqlite3.Connection`.
Migration requires no active caller transaction, enables foreign-key
verification before beginning its own transaction, and never logs customer row
contents or secret-derived hashes.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


CURRENT_SCHEMA_VERSION = 3
MIGRATION_NAME = "semantic_identifier_schema_v3"

LEGACY_TABLE_NAMES = frozenset({"orgs", "scans", "keys"})
CANONICAL_BASE_TABLE_NAMES = frozenset(
    {"tenant_organizations", "security_scans", "access_keys"}
)
CANONICAL_TABLE_NAMES = frozenset(
    {
        *CANONICAL_BASE_TABLE_NAMES,
        "schema_migrations",
        "retention_policies",
        "legal_holds",
        "audit_events",
        "audit_chain_checkpoints",
        "purge_previews",
        "purge_receipts",
    }
)
CANONICAL_INDEX_NAMES = frozenset(
    {
        "security_scans_tenant_order_idx",
        "audit_events_tenant_sequence_idx",
        "legal_holds_tenant_state_idx",
        "purge_receipts_tenant_execution_idx",
    }
)
CANONICAL_TRIGGER_NAMES = frozenset(
    {"audit_events_prevent_update", "audit_events_prevent_delete"}
)

_LEGACY_TO_CANONICAL = {
    "orgs": "tenant_organizations",
    "scans": "security_scans",
}
_REQUIRED_LEGACY_COLUMNS = {
    "orgs": frozenset(
        {"id", "name", "api_key_hash", "created_at", "webhook_url"}
    ),
    "scans": frozenset(
        {
            "id",
            "org_id",
            "created_at",
            "repo",
            "commit_sha",
            "total",
            "deploy_blocking",
            "severity_counts",
            "new_blocking",
            "findings",
        }
    ),
    "keys": frozenset(
        {"id", "org_id", "key_hash", "role", "label", "created_at"}
    ),
}
_V2_BASE_COLUMNS = {
    "tenant_organizations": frozenset(
        {"id", "name", "api_key_hash", "created_at", "webhook_url"}
    ),
    "security_scans": frozenset(
        {
            "id",
            "org_id",
            "created_at",
            "repo",
            "commit_sha",
            "total",
            "deploy_blocking",
            "severity_counts",
            "new_blocking",
            "findings",
        }
    ),
    "access_keys": frozenset(
        {"id", "org_id", "key_hash", "role", "label", "created_at"}
    ),
}
_SEMANTIC_BASE_COLUMNS = {
    "tenant_organizations": frozenset(
        {
            "organization_id",
            "organization_name",
            "api_key_hash",
            "created_at",
            "webhook_url",
        }
    ),
    "security_scans": frozenset(
        {
            "scan_id",
            "org_id",
            "created_at",
            "repository_name",
            "commit_sha",
            "finding_count",
            "deploy_blocking",
            "severity_counts",
            "new_blocking",
            "scan_findings_json",
        }
    ),
    "access_keys": frozenset(
        {
            "api_key_id",
            "org_id",
            "key_hash",
            "role_code",
            "access_key_label",
            "created_at",
        }
    ),
}
_COLUMN_RENAMES = {
    "tenant_organizations": {
        "id": "organization_id",
        "name": "organization_name",
    },
    "security_scans": {
        "id": "scan_id",
        "repo": "repository_name",
        "total": "finding_count",
        "findings": "scan_findings_json",
    },
    "access_keys": {
        "id": "api_key_id",
        "role": "role_code",
        "label": "access_key_label",
    },
    "retention_policies": {"revision": "policy_revision"},
    "legal_holds": {
        "revision": "legal_hold_revision",
        "reason": "hold_reason",
    },
}


class SchemaMigrationError(RuntimeError):
    """Raised when schema inspection or migration cannot complete safely."""


@dataclass(frozen=True)
class SchemaInspection:
    """A deterministic, row-content-free snapshot of SQLite schema metadata."""

    user_version: int
    foreign_keys_enabled: bool
    table_names: frozenset[str]
    index_names: frozenset[str]
    trigger_names: frozenset[str]
    table_columns: Mapping[str, frozenset[str]]


@dataclass(frozen=True)
class SchemaMigrationResult:
    """Describe one completed migration attempt without exposing tenant data."""

    previous_version: int
    current_version: int
    changed: bool
    migrated_legacy_schema: bool


def _require_connection(connection: sqlite3.Connection) -> sqlite3.Connection:
    """Return a live SQLite connection or raise a bounded public error."""
    if not isinstance(connection, sqlite3.Connection):
        raise ValueError("connection must be a sqlite3.Connection")
    try:
        connection.execute("PRAGMA schema_version").fetchone()
    except sqlite3.ProgrammingError as exc:
        raise SchemaMigrationError("closed connection") from exc
    return connection


def _quoted_identifier(identifier: str) -> str:
    """Quote one identifier obtained from SQLite's own schema catalog."""
    return '"' + identifier.replace('"', '""') + '"'


def inspect_controlplane_schema(
    connection: sqlite3.Connection,
) -> SchemaInspection:
    """Return tables, indexes, triggers, columns, and active pragma state."""
    connection = _require_connection(connection)
    try:
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        foreign_keys_enabled = bool(
            connection.execute("PRAGMA foreign_keys").fetchone()[0]
        )
        schema_objects = tuple(
            connection.execute(
                "SELECT type, name FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
        )
        table_names = frozenset(
            object_name
            for object_type, object_name in schema_objects
            if object_type == "table"
        )
        index_names = frozenset(
            object_name
            for object_type, object_name in schema_objects
            if object_type == "index"
        )
        trigger_names = frozenset(
            object_name
            for object_type, object_name in schema_objects
            if object_type == "trigger"
        )
        table_columns = {
            table_name: frozenset(
                str(column_row[0])
                for column_row in connection.execute(
                    "SELECT name FROM pragma_table_info(?)", (table_name,)
                )
            )
            for table_name in table_names
        }
    except sqlite3.ProgrammingError as exc:
        raise SchemaMigrationError("closed connection") from exc
    except sqlite3.DatabaseError as exc:
        raise SchemaMigrationError("schema inspection failed") from exc
    return SchemaInspection(
        user_version=user_version,
        foreign_keys_enabled=foreign_keys_enabled,
        table_names=table_names,
        index_names=index_names,
        trigger_names=trigger_names,
        table_columns=MappingProxyType(table_columns),
    )


def _columns_match(
    inspection: SchemaInspection, required_columns: Mapping[str, frozenset[str]]
) -> bool:
    """Return whether every named table has exactly the expected columns."""
    return all(
        inspection.table_columns.get(table_name, frozenset()) == expected_columns
        for table_name, expected_columns in required_columns.items()
    )


def _validate_preconditions(inspection: SchemaInspection) -> str:
    """Classify the database as fresh, legacy, v2 canonical, or semantic."""
    if inspection.user_version > CURRENT_SCHEMA_VERSION:
        raise SchemaMigrationError(
            "database uses a newer schema version than this AppGuardrail build"
        )

    legacy_present = LEGACY_TABLE_NAMES & inspection.table_names
    canonical_present = CANONICAL_BASE_TABLE_NAMES & inspection.table_names
    if legacy_present and canonical_present:
        raise SchemaMigrationError("mixed schema contains legacy and canonical tables")

    if legacy_present:
        if legacy_present != LEGACY_TABLE_NAMES:
            missing_tables = sorted(LEGACY_TABLE_NAMES - legacy_present)
            raise SchemaMigrationError(
                "incomplete legacy schema; missing tables: "
                + ", ".join(missing_tables)
            )
        for table_name, required_columns in _REQUIRED_LEGACY_COLUMNS.items():
            missing_columns = required_columns - inspection.table_columns.get(
                table_name, frozenset()
            )
            if missing_columns:
                raise SchemaMigrationError(
                    f"legacy table {table_name} is missing required columns: "
                    + ", ".join(sorted(missing_columns))
                )
        return "legacy"

    if canonical_present:
        if canonical_present != CANONICAL_BASE_TABLE_NAMES:
            missing_tables = sorted(CANONICAL_BASE_TABLE_NAMES - canonical_present)
            raise SchemaMigrationError(
                "incomplete canonical schema; missing tables: "
                + ", ".join(missing_tables)
            )
        if _columns_match(inspection, _SEMANTIC_BASE_COLUMNS):
            return "semantic"
        if _columns_match(inspection, _V2_BASE_COLUMNS):
            return "canonical_v2"
        raise SchemaMigrationError("canonical schema contains ambiguous base columns")

    return "fresh"


def _enable_foreign_keys(connection: sqlite3.Connection) -> None:
    """Enable and verify per-connection SQLite foreign-key enforcement."""
    connection.execute("PRAGMA foreign_keys = ON")
    foreign_keys_enabled = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    if foreign_keys_enabled != 1:
        raise SchemaMigrationError("foreign key enforcement could not be enabled")


def _create_access_keys_table(connection: sqlite3.Connection) -> None:
    """Create the semantic access-key table and authorization constraints."""
    connection.execute(
        """
        CREATE TABLE access_keys (
            api_key_id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL REFERENCES tenant_organizations(organization_id),
            key_hash TEXT NOT NULL UNIQUE,
            role_code TEXT NOT NULL CHECK(role_code IN ('owner','member','viewer')),
            access_key_label TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )


def _create_base_tables(connection: sqlite3.Connection) -> None:
    """Create the semantic equivalents of the embedded legacy base schema."""
    connection.execute(
        """
        CREATE TABLE tenant_organizations (
            organization_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_name TEXT NOT NULL,
            api_key_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            webhook_url TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE security_scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL REFERENCES tenant_organizations(organization_id),
            created_at TEXT NOT NULL,
            repository_name TEXT,
            commit_sha TEXT,
            finding_count INTEGER NOT NULL,
            deploy_blocking INTEGER NOT NULL,
            severity_counts TEXT NOT NULL,
            new_blocking INTEGER NOT NULL DEFAULT 0,
            scan_findings_json TEXT NOT NULL
        )
        """
    )
    _create_access_keys_table(connection)


def _rename_column(
    connection: sqlite3.Connection,
    table_name: str,
    old_column_name: str,
    new_column_name: str,
) -> None:
    """Rename one validated organization-owned column inside the transaction."""
    connection.execute(
        f"ALTER TABLE {_quoted_identifier(table_name)} "
        f"RENAME COLUMN {_quoted_identifier(old_column_name)} "
        f"TO {_quoted_identifier(new_column_name)}"
    )


def _rename_columns(
    connection: sqlite3.Connection, table_names: tuple[str, ...]
) -> None:
    """Apply the reviewed v2-to-v3 semantic column mapping."""
    for table_name in table_names:
        for old_column_name, new_column_name in _COLUMN_RENAMES[table_name].items():
            _rename_column(
                connection,
                table_name,
                old_column_name,
                new_column_name,
            )


def _migrate_legacy_access_keys(connection: sqlite3.Connection) -> None:
    """Rebuild shipped legacy keys under semantic names and v3 constraints."""
    _create_access_keys_table(connection)
    connection.execute(
        """
        INSERT INTO access_keys(
            api_key_id, org_id, key_hash, role_code, access_key_label, created_at
        )
        SELECT id, org_id, key_hash, role, COALESCE(label, ''), created_at
        FROM keys
        """
    )
    connection.execute("DROP TABLE keys")


def _rename_legacy_tables(connection: sqlite3.Connection) -> None:
    """Move the shipped legacy schema directly to semantic canonical v3."""
    for legacy_table_name in ("orgs", "scans"):
        canonical_table_name = _LEGACY_TO_CANONICAL[legacy_table_name]
        connection.execute(
            f"ALTER TABLE {_quoted_identifier(legacy_table_name)} "
            f"RENAME TO {_quoted_identifier(canonical_table_name)}"
        )
    _rename_columns(connection, ("tenant_organizations", "security_scans"))
    _migrate_legacy_access_keys(connection)
    connection.execute("DROP INDEX IF EXISTS idx_scans_org")


def _create_governance_objects(connection: sqlite3.Connection) -> None:
    """Create retention, legal-hold, purge, and audit persistence objects."""
    statements = (
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            schema_version INTEGER PRIMARY KEY,
            migration_name TEXT NOT NULL UNIQUE,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS retention_policies (
            tenant_id INTEGER PRIMARY KEY
                REFERENCES tenant_organizations(organization_id) ON DELETE CASCADE,
            policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
            scan_history_days INTEGER NOT NULL CHECK(scan_history_days > 0),
            audit_event_days INTEGER NOT NULL CHECK(audit_event_days > 0),
            access_key_metadata_days INTEGER NOT NULL
                CHECK(access_key_metadata_days > 0),
            webhook_metadata_days INTEGER NOT NULL
                CHECK(webhook_metadata_days > 0),
            suppression_evidence_days INTEGER NOT NULL
                CHECK(suppression_evidence_days > 0),
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS legal_holds (
            legal_hold_id TEXT PRIMARY KEY,
            tenant_id INTEGER NOT NULL
                REFERENCES tenant_organizations(organization_id) ON DELETE CASCADE,
            legal_hold_revision INTEGER NOT NULL CHECK(legal_hold_revision > 0),
            hold_state TEXT NOT NULL CHECK(hold_state IN ('active','released')),
            data_category TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            hold_reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            released_at TEXT,
            released_by TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            audit_event_id TEXT PRIMARY KEY,
            tenant_id INTEGER NOT NULL
                REFERENCES tenant_organizations(organization_id) ON DELETE RESTRICT,
            sequence_number INTEGER NOT NULL CHECK(sequence_number > 0),
            event_type TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            previous_event_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            UNIQUE(tenant_id, sequence_number),
            UNIQUE(tenant_id, event_hash)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
            checkpoint_id TEXT PRIMARY KEY,
            tenant_id INTEGER NOT NULL
                REFERENCES tenant_organizations(organization_id) ON DELETE CASCADE,
            through_sequence_number INTEGER NOT NULL
                CHECK(through_sequence_number > 0),
            event_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            UNIQUE(tenant_id, through_sequence_number)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS purge_previews (
            preview_id TEXT PRIMARY KEY,
            tenant_id INTEGER NOT NULL
                REFERENCES tenant_organizations(organization_id) ON DELETE CASCADE,
            policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
            legal_hold_revision INTEGER NOT NULL CHECK(legal_hold_revision >= 0),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            cutoffs_json TEXT NOT NULL,
            eligible_counts_json TEXT NOT NULL,
            held_counts_json TEXT NOT NULL,
            preview_hash TEXT NOT NULL UNIQUE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS purge_receipts (
            receipt_id TEXT PRIMARY KEY,
            tenant_id INTEGER NOT NULL
                REFERENCES tenant_organizations(organization_id) ON DELETE CASCADE,
            preview_id TEXT NOT NULL REFERENCES purge_previews(preview_id),
            executed_at TEXT NOT NULL,
            executed_by TEXT NOT NULL,
            deleted_counts_json TEXT NOT NULL,
            held_counts_json TEXT NOT NULL,
            receipt_hash TEXT NOT NULL UNIQUE
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS security_scans_tenant_order_idx
            ON security_scans(org_id, scan_id DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS audit_events_tenant_sequence_idx
            ON audit_events(tenant_id, sequence_number)
        """,
        """
        CREATE INDEX IF NOT EXISTS legal_holds_tenant_state_idx
            ON legal_holds(tenant_id, hold_state)
        """,
        """
        CREATE INDEX IF NOT EXISTS purge_receipts_tenant_execution_idx
            ON purge_receipts(tenant_id, executed_at DESC)
        """,
        """
        CREATE TRIGGER IF NOT EXISTS audit_events_prevent_update
        BEFORE UPDATE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'audit_events are append-only');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS audit_events_prevent_delete
        BEFORE DELETE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'audit_events are append-only');
        END
        """,
    )
    for schema_statement in statements:
        connection.execute(schema_statement)


def _validate_required_objects(inspection: SchemaInspection, version_label: str) -> None:
    """Reject a canonical database whose required objects are incomplete."""
    missing_tables = CANONICAL_TABLE_NAMES - inspection.table_names
    missing_indexes = CANONICAL_INDEX_NAMES - inspection.index_names
    missing_triggers = CANONICAL_TRIGGER_NAMES - inspection.trigger_names
    if missing_tables or missing_indexes or missing_triggers:
        missing_objects = sorted(missing_tables | missing_indexes | missing_triggers)
        raise SchemaMigrationError(
            f"schema version {version_label} is incomplete; missing objects: "
            + ", ".join(missing_objects)
        )
    if LEGACY_TABLE_NAMES & inspection.table_names or "idx_scans_org" in inspection.index_names:
        raise SchemaMigrationError(
            f"schema version {version_label} still contains legacy objects"
        )


def _validate_v2_schema(inspection: SchemaInspection) -> None:
    """Validate the complete pre-v3 canonical schema before column renames."""
    _validate_required_objects(inspection, "2")
    if not _columns_match(inspection, _V2_BASE_COLUMNS):
        raise SchemaMigrationError("schema version 2 has unexpected base columns")
    for table_name, old_column_name in (
        ("retention_policies", "revision"),
        ("legal_holds", "revision"),
        ("legal_holds", "reason"),
    ):
        if old_column_name not in inspection.table_columns.get(table_name, frozenset()):
            raise SchemaMigrationError(
                f"schema version 2 is missing {table_name}.{old_column_name}"
            )


def _validate_current_schema(inspection: SchemaInspection) -> None:
    """Reject a version-three database with missing or generic owned columns."""
    _validate_required_objects(inspection, "3")
    if not _columns_match(inspection, _SEMANTIC_BASE_COLUMNS):
        raise SchemaMigrationError("schema version 3 has unexpected base columns")
    required_semantic_columns = {
        "retention_policies": {"policy_revision"},
        "legal_holds": {"legal_hold_revision", "hold_reason"},
    }
    for table_name, column_names in required_semantic_columns.items():
        if not column_names <= inspection.table_columns.get(table_name, frozenset()):
            raise SchemaMigrationError(
                f"schema version 3 is missing semantic columns in {table_name}"
            )


def _record_schema_migration(connection: sqlite3.Connection) -> None:
    """Record v3 exactly once while rejecting contradictory migration history."""
    version_row = connection.execute(
        "SELECT migration_name FROM schema_migrations WHERE schema_version = ?",
        (CURRENT_SCHEMA_VERSION,),
    ).fetchone()
    if version_row is not None:
        if str(version_row[0]) != MIGRATION_NAME:
            raise SchemaMigrationError("conflicting schema migration metadata")
        return

    name_row = connection.execute(
        "SELECT schema_version FROM schema_migrations WHERE migration_name = ?",
        (MIGRATION_NAME,),
    ).fetchone()
    if name_row is not None:
        raise SchemaMigrationError("conflicting schema migration metadata")

    connection.execute(
        "INSERT INTO schema_migrations(schema_version, migration_name) VALUES (?, ?)",
        (CURRENT_SCHEMA_VERSION, MIGRATION_NAME),
    )


def _migrate_v2_columns(connection: sqlite3.Connection) -> None:
    """Rename every reviewed v2 generic column while preserving rows and FKs."""
    _rename_columns(
        connection,
        (
            "tenant_organizations",
            "security_scans",
            "access_keys",
            "retention_policies",
            "legal_holds",
        ),
    )


def migrate_controlplane_schema(
    connection: sqlite3.Connection,
) -> SchemaMigrationResult:
    """Atomically create or migrate the semantic retention/audit schema."""
    connection = _require_connection(connection)
    try:
        active_transaction = connection.in_transaction
    except sqlite3.ProgrammingError as exc:
        raise SchemaMigrationError("closed connection") from exc
    if active_transaction:
        raise SchemaMigrationError("cannot migrate inside an active transaction")

    _enable_foreign_keys(connection)

    transaction_started = False
    locked_inspection: SchemaInspection | None = None
    schema_kind = ""
    try:
        connection.execute("BEGIN IMMEDIATE")
        transaction_started = True
        locked_inspection = inspect_controlplane_schema(connection)
        schema_kind = _validate_preconditions(locked_inspection)

        if locked_inspection.user_version == CURRENT_SCHEMA_VERSION:
            _validate_current_schema(locked_inspection)
            connection.rollback()
            transaction_started = False
            return SchemaMigrationResult(
                previous_version=CURRENT_SCHEMA_VERSION,
                current_version=CURRENT_SCHEMA_VERSION,
                changed=False,
                migrated_legacy_schema=False,
            )

        if schema_kind == "legacy":
            _rename_legacy_tables(connection)
            _create_governance_objects(connection)
        elif schema_kind == "fresh":
            _create_base_tables(connection)
            _create_governance_objects(connection)
        elif schema_kind == "canonical_v2":
            _validate_v2_schema(locked_inspection)
            _migrate_v2_columns(connection)
        elif schema_kind == "semantic":
            _validate_current_schema(locked_inspection)

        _record_schema_migration(connection)
        connection.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
        foreign_key_violations = tuple(connection.execute("PRAGMA foreign_key_check"))
        if foreign_key_violations:
            raise SchemaMigrationError("foreign key check failed")
        connection.commit()
        transaction_started = False
        return SchemaMigrationResult(
            previous_version=locked_inspection.user_version,
            current_version=CURRENT_SCHEMA_VERSION,
            changed=True,
            migrated_legacy_schema=schema_kind == "legacy",
        )
    except Exception as exc:
        if transaction_started and connection.in_transaction:
            connection.rollback()
        if isinstance(exc, SchemaMigrationError):
            raise
        raise SchemaMigrationError("control-plane schema migration failed") from exc


__all__ = [
    "CANONICAL_INDEX_NAMES",
    "CANONICAL_TABLE_NAMES",
    "CANONICAL_TRIGGER_NAMES",
    "CURRENT_SCHEMA_VERSION",
    "MIGRATION_NAME",
    "SchemaInspection",
    "SchemaMigrationError",
    "SchemaMigrationResult",
    "inspect_controlplane_schema",
    "migrate_controlplane_schema",
]
