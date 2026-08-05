"""Apply bounded CodeRabbit fixes for the retention schema migration."""

from __future__ import annotations

from pathlib import Path


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    """Replace one exact reviewed contract or fail without partial output."""
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} changed: expected one match, found {count}")
    return text.replace(old, new, 1)


def _repair_schema() -> None:
    """Serialize schema classification and retain append-only audit records."""
    path = Path("appguardrail_core/controlplane_schema.py")
    text = path.read_text(encoding="utf-8")
    text = _replace_once(
        text,
        """        CREATE TABLE IF NOT EXISTS audit_events (
            audit_event_id TEXT PRIMARY KEY,
            tenant_id INTEGER NOT NULL
                REFERENCES tenant_organizations(id) ON DELETE CASCADE,
""",
        """        CREATE TABLE IF NOT EXISTS audit_events (
            audit_event_id TEXT PRIMARY KEY,
            tenant_id INTEGER NOT NULL
                REFERENCES tenant_organizations(id) ON DELETE RESTRICT,
""",
        "audit event deletion policy",
    )
    old_migration = '''    initial = inspect_controlplane_schema(connection)
    schema_kind = _validate_preconditions(initial)
    _enable_foreign_keys(connection)

    if initial.user_version == CURRENT_SCHEMA_VERSION:
        current = inspect_controlplane_schema(connection)
        _validate_current_schema(current)
        return SchemaMigrationResult(
            previous_version=CURRENT_SCHEMA_VERSION,
            current_version=CURRENT_SCHEMA_VERSION,
            changed=False,
            migrated_legacy_schema=False,
        )

    transaction_started = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        transaction_started = True
        if schema_kind == "legacy":
            _rename_legacy_tables(connection)
        elif schema_kind == "fresh":
            _create_base_tables(connection)
        _create_governance_objects(connection)
        connection.execute(
            "INSERT INTO schema_migrations(schema_version, migration_name) "
            "VALUES (?, ?)",
            (CURRENT_SCHEMA_VERSION, MIGRATION_NAME),
        )
        connection.execute("PRAGMA user_version = 2")
        violations = tuple(connection.execute("PRAGMA foreign_key_check"))
        if violations:
            raise SchemaMigrationError("foreign key check failed")
        connection.commit()
    except Exception as exc:
        if transaction_started and connection.in_transaction:
            connection.rollback()
        if isinstance(exc, SchemaMigrationError):
            raise
        raise SchemaMigrationError("control-plane schema migration failed") from exc

    return SchemaMigrationResult(
        previous_version=initial.user_version,
        current_version=CURRENT_SCHEMA_VERSION,
        changed=True,
        migrated_legacy_schema=schema_kind == "legacy",
    )
'''
    new_migration = '''    _enable_foreign_keys(connection)

    transaction_started = False
    locked: SchemaInspection | None = None
    schema_kind = ""
    try:
        connection.execute("BEGIN IMMEDIATE")
        transaction_started = True
        locked = inspect_controlplane_schema(connection)
        schema_kind = _validate_preconditions(locked)
        if locked.user_version == CURRENT_SCHEMA_VERSION:
            _validate_current_schema(locked)
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
        elif schema_kind == "fresh":
            _create_base_tables(connection)
        _create_governance_objects(connection)
        connection.execute(
            "INSERT INTO schema_migrations(schema_version, migration_name) "
            "VALUES (?, ?)",
            (CURRENT_SCHEMA_VERSION, MIGRATION_NAME),
        )
        connection.execute("PRAGMA user_version = 2")
        violations = tuple(connection.execute("PRAGMA foreign_key_check"))
        if violations:
            raise SchemaMigrationError("foreign key check failed")
        connection.commit()
        transaction_started = False
    except Exception as exc:
        if transaction_started and connection.in_transaction:
            connection.rollback()
        if isinstance(exc, SchemaMigrationError):
            raise
        raise SchemaMigrationError("control-plane schema migration failed") from exc

    if locked is None:  # pragma: no cover - guarded by the transaction flow above
        raise SchemaMigrationError("schema inspection did not complete")
    return SchemaMigrationResult(
        previous_version=locked.user_version,
        current_version=CURRENT_SCHEMA_VERSION,
        changed=True,
        migrated_legacy_schema=schema_kind == "legacy",
    )
'''
    text = _replace_once(text, old_migration, new_migration, "migration transaction")
    path.write_text(text, encoding="utf-8")


def _repair_regex_contracts() -> None:
    """Make pytest error-message assertions match the literal public type name."""
    for filename in (
        "tests/test_controlplane_schema_coverage_edges.py",
        "tests/test_controlplane_schema_failure_edges.py",
    ):
        path = Path(filename)
        text = path.read_text(encoding="utf-8")
        text = _replace_once(
            text,
            'match="sqlite3.Connection"',
            r'match=r"sqlite3\.Connection"',
            f"{filename} sqlite connection pattern",
        )
        path.write_text(text, encoding="utf-8")


def _append_migration_regression() -> None:
    """Add a real SQLite tenant-deletion regression for retained audit evidence."""
    path = Path("tests/test_controlplane_schema_migration.py")
    text = path.read_text(encoding="utf-8").rstrip() + "\n"
    marker = "def test_tenant_delete_is_restricted_when_audit_evidence_exists()"
    if marker in text:
        return
    text += '''


def test_tenant_delete_is_restricted_when_audit_evidence_exists() -> None:
    """Tenant deletion cannot cascade through retained append-only audit evidence."""
    connection = _connection()
    migrate_controlplane_schema(connection)
    connection.execute(
        "INSERT INTO tenant_organizations(name, api_key_hash, created_at) "
        "VALUES ('Acme', 'hash', '2026-08-04T12:00:00Z')"
    )
    connection.execute(
        "INSERT INTO audit_events(audit_event_id, tenant_id, sequence_number, "
        "event_type, actor_id, request_id, occurred_at, summary_json, "
        "previous_event_hash, event_hash) VALUES (?, 1, 1, ?, ?, ?, ?, ?, ?, ?)",
        (
            "audit-event-retained",
            "retention.policy.updated",
            "owner-key-7",
            "request-retained",
            "2026-08-04T12:10:00Z",
            '{"policy_revision":1}',
            "0" * 64,
            "2" * 64,
        ),
    )
    connection.commit()

    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
        connection.execute("DELETE FROM tenant_organizations WHERE id = 1")

    assert connection.execute(
        "SELECT COUNT(*) FROM tenant_organizations WHERE id = 1"
    ).fetchone()[0] == 1
    assert connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE audit_event_id = ?",
        ("audit-event-retained",),
    ).fetchone()[0] == 1
'''
    if "import pytest\n" not in text:
        text = text.replace("import sqlite3\n", "import sqlite3\n\nimport pytest\n", 1)
    path.write_text(text, encoding="utf-8")


def _append_concurrency_regression() -> None:
    """Simulate a competing migrator completing immediately before lock acquisition."""
    path = Path("tests/test_controlplane_schema_failure_edges.py")
    text = path.read_text(encoding="utf-8").rstrip() + "\n"
    marker = "class ConcurrentCompletionConnection"
    if marker in text:
        return
    text += '''


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
'''
    path.write_text(text, encoding="utf-8")


def _update_docs() -> None:
    """Document the locked snapshot and immutable audit deletion policy."""
    path = Path("docs/controlplane-schema-migration.md")
    text = path.read_text(encoding="utf-8")
    text = _replace_once(
        text,
        "5. Acquire a write reservation with `BEGIN IMMEDIATE`.\n6. Rename validated legacy tables or create the canonical base schema for a fresh database.",
        "5. Acquire a write reservation with `BEGIN IMMEDIATE`.\n6. Reinspect and classify the schema while holding the write reservation so concurrent migrators become an idempotent no-op.\n7. Rename validated legacy tables or create the canonical base schema for a fresh database.",
        "operator sequence",
    )
    text = text.replace("7. Create governance tables", "8. Create governance tables", 1)
    text = text.replace("8. Record the migration", "9. Record the migration", 1)
    text = text.replace("9. Run `PRAGMA foreign_key_check`", "10. Run `PRAGMA foreign_key_check`", 1)
    text = text.replace("10. Commit every schema change", "11. Commit every schema change", 1)
    insertion = """

Audit events reference `tenant_organizations` with `ON DELETE RESTRICT` and remain protected by update/delete triggers. Tenant deletion and ordinary retention purges therefore cannot erase audit evidence. A future privileged audit-expiration mechanism must define a separately reviewed authorization, checkpoint, receipt, and chain-resealing contract before it can delete any audit row.
"""
    anchor = "\n## Idempotence and failure semantics\n"
    if insertion.strip() not in text:
        text = text.replace(anchor, insertion + anchor, 1)
    path.write_text(text, encoding="utf-8")

    changelog = Path("CHANGELOG.d/871-retention-schema-migration.md")
    text = changelog.read_text(encoding="utf-8").rstrip() + "\n"
    line = "- Serialized schema classification under `BEGIN IMMEDIATE` and changed audit-event tenant deletion to `RESTRICT` so concurrent migrators are idempotent and ordinary tenant deletion cannot erase append-only audit evidence.\n"
    if line not in text:
        text += line
    changelog.write_text(text, encoding="utf-8")


def main() -> None:
    """Apply every reviewed schema fix in a deterministic order."""
    _repair_schema()
    _repair_regex_contracts()
    _append_migration_regression()
    _append_concurrency_regression()
    _update_docs()


if __name__ == "__main__":
    main()
