"""Real SQLite contracts for canonical control-plane schema migration."""

from __future__ import annotations

import json
import sqlite3

import pytest
from pathlib import Path

from appguardrail_core.controlplane_schema import (
    CANONICAL_INDEX_NAMES,
    CANONICAL_TABLE_NAMES,
    CANONICAL_TRIGGER_NAMES,
    CURRENT_SCHEMA_VERSION,
    inspect_controlplane_schema,
    migrate_controlplane_schema,
)


LEGACY_SCHEMA = """
CREATE TABLE orgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    webhook_url TEXT
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
CREATE INDEX idx_scans_org ON scans(org_id, id DESC);
CREATE TABLE keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES orgs(id),
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('owner','member','viewer')),
    label TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _connection(path: Path | str = ":memory:") -> sqlite3.Connection:
    """Return a deterministic SQLite connection using row objects."""
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def _legacy_connection(path: Path | str = ":memory:") -> sqlite3.Connection:
    """Create the reviewed legacy schema with realistic tenant data."""
    connection = _connection(path)
    connection.executescript(LEGACY_SCHEMA)
    severity_counts = json.dumps(
        {"CRITICAL": 1, "HIGH": 2, "WARNING": 3, "INFO": 4},
        sort_keys=True,
    )
    findings = json.dumps(
        [
            {
                "rule_id": "tenant-authz",
                "severity": "HIGH",
                "file": "api/projects.py",
                "line": 41,
            }
        ],
        sort_keys=True,
    )
    connection.execute(
        "INSERT INTO orgs(name, api_key_hash, created_at, webhook_url) "
        "VALUES (?, ?, ?, ?)",
        (
            "Acme Security",
            "bootstrap-hash-001",
            "2026-08-04T12:00:00Z",
            "https://8.8.8.8/tenant-acme",
        ),
    )
    connection.execute(
        "INSERT INTO scans(org_id, created_at, repo, commit_sha, total, "
        "deploy_blocking, severity_counts, new_blocking, findings) "
        "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "2026-08-04T12:05:00Z",
            "ContextualWisdomLab/appguardrail",
            "abc123def456",
            10,
            3,
            severity_counts,
            2,
            findings,
        ),
    )
    connection.execute(
        "INSERT INTO keys(org_id, key_hash, role, label, created_at) "
        "VALUES (1, ?, ?, ?, ?)",
        (
            "member-hash-002",
            "member",
            "deployment-agent",
            "2026-08-04T12:06:00Z",
        ),
    )
    connection.commit()
    return connection


def test_fresh_database_receives_only_canonical_multiword_objects() -> None:
    """A new embedded deployment starts on the canonical version-two schema."""
    connection = _connection()

    result = migrate_controlplane_schema(connection)
    inspection = inspect_controlplane_schema(connection)

    assert result.previous_version == 0
    assert result.current_version == CURRENT_SCHEMA_VERSION == 2
    assert result.migrated_legacy_schema is False
    assert inspection.user_version == CURRENT_SCHEMA_VERSION
    assert inspection.foreign_keys_enabled is True
    assert CANONICAL_TABLE_NAMES <= inspection.table_names
    assert CANONICAL_INDEX_NAMES <= inspection.index_names
    assert CANONICAL_TRIGGER_NAMES <= inspection.trigger_names
    assert {"orgs", "scans", "keys"}.isdisjoint(inspection.table_names)
    assert "idx_scans_org" not in inspection.index_names
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    migration = connection.execute(
        "SELECT schema_version, migration_name FROM schema_migrations"
    ).fetchone()
    assert tuple(migration) == (2, "retention_audit_schema_v2")


def test_legacy_database_migrates_rows_and_foreign_keys_without_data_loss(
    tmp_path: Path,
) -> None:
    """Existing tenant, scan, webhook, drift, findings, role, and key data survives."""
    database_path = tmp_path / "legacy-control-plane.db"
    connection = _legacy_connection(database_path)

    result = migrate_controlplane_schema(connection)

    assert result.migrated_legacy_schema is True
    organization = connection.execute(
        "SELECT id, name, api_key_hash, created_at, webhook_url "
        "FROM tenant_organizations"
    ).fetchone()
    scan = connection.execute(
        "SELECT id, org_id, created_at, repo, commit_sha, total, "
        "deploy_blocking, severity_counts, new_blocking, findings "
        "FROM security_scans"
    ).fetchone()
    access_key = connection.execute(
        "SELECT id, org_id, key_hash, role, label, created_at FROM access_keys"
    ).fetchone()

    assert tuple(organization) == (
        1,
        "Acme Security",
        "bootstrap-hash-001",
        "2026-08-04T12:00:00Z",
        "https://8.8.8.8/tenant-acme",
    )
    assert tuple(scan[:7]) == (
        1,
        1,
        "2026-08-04T12:05:00Z",
        "ContextualWisdomLab/appguardrail",
        "abc123def456",
        10,
        3,
    )
    assert json.loads(scan[7]) == {
        "CRITICAL": 1,
        "HIGH": 2,
        "WARNING": 3,
        "INFO": 4,
    }
    assert scan[8] == 2
    assert json.loads(scan[9])[0]["rule_id"] == "tenant-authz"
    assert tuple(access_key) == (
        1,
        1,
        "member-hash-002",
        "member",
        "deployment-agent",
        "2026-08-04T12:06:00Z",
    )

    scan_foreign_key = connection.execute(
        "PRAGMA foreign_key_list(security_scans)"
    ).fetchone()
    key_foreign_key = connection.execute("PRAGMA foreign_key_list(access_keys)").fetchone()
    assert scan_foreign_key[2] == "tenant_organizations"
    assert key_foreign_key[2] == "tenant_organizations"
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    connection.close()
    reopened = _connection(database_path)
    assert reopened.execute("PRAGMA user_version").fetchone()[0] == 2
    assert reopened.execute("SELECT COUNT(*) FROM security_scans").fetchone()[0] == 1


def test_second_migration_is_idempotent_and_reports_no_schema_change() -> None:
    """Restarting the service cannot duplicate migrations, triggers, or indexes."""
    connection = _connection()
    first = migrate_controlplane_schema(connection)
    first_schema = tuple(
        connection.execute(
            "SELECT type, name, sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        )
    )

    second = migrate_controlplane_schema(connection)
    second_schema = tuple(
        connection.execute(
            "SELECT type, name, sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        )
    )

    assert first.changed is True
    assert second.changed is False
    assert second.previous_version == 2
    assert second.current_version == 2
    assert second_schema == first_schema
    assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 1


def test_new_audit_events_are_append_only_at_the_database_boundary() -> None:
    """SQLite itself rejects mutation or deletion of persisted audit evidence."""
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
            "audit-event-1",
            "retention.policy.updated",
            "owner-key-7",
            "request-1",
            "2026-08-04T12:10:00Z",
            '{"policy_revision":1}',
            "0" * 64,
            "1" * 64,
        ),
    )
    connection.commit()

    for statement in (
        "UPDATE audit_events SET event_type = 'tampered' "
        "WHERE audit_event_id = 'audit-event-1'",
        "DELETE FROM audit_events WHERE audit_event_id = 'audit-event-1'",
    ):
        try:
            connection.execute(statement)
        except sqlite3.IntegrityError as exc:
            assert "append-only" in str(exc)
        else:
            raise AssertionError("append-only audit trigger did not reject mutation")

    assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1



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
