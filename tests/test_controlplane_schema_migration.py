"""Real SQLite contracts for canonical control-plane schema migration."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

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

V2_SCHEMA = """
CREATE TABLE tenant_organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    webhook_url TEXT
);
CREATE TABLE security_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES tenant_organizations(id),
    created_at TEXT NOT NULL,
    repo TEXT,
    commit_sha TEXT,
    total INTEGER NOT NULL,
    deploy_blocking INTEGER NOT NULL,
    severity_counts TEXT NOT NULL,
    new_blocking INTEGER NOT NULL DEFAULT 0,
    findings TEXT NOT NULL
);
CREATE TABLE access_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES tenant_organizations(id),
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('owner','member','viewer')),
    label TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE schema_migrations (
    schema_version INTEGER PRIMARY KEY,
    migration_name TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE retention_policies (
    tenant_id INTEGER PRIMARY KEY REFERENCES tenant_organizations(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    scan_history_days INTEGER NOT NULL CHECK(scan_history_days > 0),
    audit_event_days INTEGER NOT NULL CHECK(audit_event_days > 0),
    access_key_metadata_days INTEGER NOT NULL CHECK(access_key_metadata_days > 0),
    webhook_metadata_days INTEGER NOT NULL CHECK(webhook_metadata_days > 0),
    suppression_evidence_days INTEGER NOT NULL CHECK(suppression_evidence_days > 0),
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE legal_holds (
    legal_hold_id TEXT PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenant_organizations(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    hold_state TEXT NOT NULL CHECK(hold_state IN ('active','released')),
    data_category TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    released_at TEXT,
    released_by TEXT
);
CREATE TABLE audit_events (
    audit_event_id TEXT PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenant_organizations(id) ON DELETE RESTRICT,
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
);
CREATE TABLE audit_chain_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenant_organizations(id) ON DELETE CASCADE,
    through_sequence_number INTEGER NOT NULL CHECK(through_sequence_number > 0),
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    UNIQUE(tenant_id, through_sequence_number)
);
CREATE TABLE purge_previews (
    preview_id TEXT PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenant_organizations(id) ON DELETE CASCADE,
    policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
    legal_hold_revision INTEGER NOT NULL CHECK(legal_hold_revision >= 0),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    cutoffs_json TEXT NOT NULL,
    eligible_counts_json TEXT NOT NULL,
    held_counts_json TEXT NOT NULL,
    preview_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE purge_receipts (
    receipt_id TEXT PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenant_organizations(id) ON DELETE CASCADE,
    preview_id TEXT NOT NULL REFERENCES purge_previews(preview_id),
    executed_at TEXT NOT NULL,
    executed_by TEXT NOT NULL,
    deleted_counts_json TEXT NOT NULL,
    held_counts_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX security_scans_tenant_order_idx ON security_scans(org_id, id DESC);
CREATE INDEX audit_events_tenant_sequence_idx ON audit_events(tenant_id, sequence_number);
CREATE INDEX legal_holds_tenant_state_idx ON legal_holds(tenant_id, hold_state);
CREATE INDEX purge_receipts_tenant_execution_idx ON purge_receipts(tenant_id, executed_at DESC);
CREATE TRIGGER audit_events_prevent_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END;
CREATE TRIGGER audit_events_prevent_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END;
INSERT INTO schema_migrations(schema_version, migration_name)
VALUES (2, 'retention_audit_schema_v2');
PRAGMA user_version = 2;
"""


def _connection(path: Path | str = ":memory:") -> sqlite3.Connection:
    """Return a deterministic SQLite connection using row objects."""
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def _insert_realistic_v1_rows(connection: sqlite3.Connection) -> None:
    """Insert representative tenant, scan, and key rows in the v1 layout."""
    severity_counts = json.dumps(
        {"CRITICAL": 1, "HIGH": 2, "WARNING": 3, "INFO": 4}, sort_keys=True
    )
    scan_findings = json.dumps(
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
            "https://hooks.example.test/tenant-acme",
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
            scan_findings,
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


def _legacy_connection(path: Path | str = ":memory:") -> sqlite3.Connection:
    """Create the reviewed shipped legacy schema with realistic tenant data."""
    connection = _connection(path)
    connection.executescript(LEGACY_SCHEMA)
    _insert_realistic_v1_rows(connection)
    return connection


def test_fresh_database_receives_only_canonical_multiword_objects() -> None:
    """A new embedded deployment starts directly on the semantic v3 schema."""
    connection = _connection()

    result = migrate_controlplane_schema(connection)
    inspection = inspect_controlplane_schema(connection)

    assert result.previous_version == 0
    assert result.current_version == CURRENT_SCHEMA_VERSION == 3
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
    assert tuple(migration) == (3, "semantic_identifier_schema_v3")


def test_legacy_database_migrates_rows_and_foreign_keys_without_data_loss(
    tmp_path: Path,
) -> None:
    """Existing tenant, scan, webhook, findings, role, and key data survives."""
    database_path = tmp_path / "legacy-control-plane.db"
    connection = _legacy_connection(database_path)

    result = migrate_controlplane_schema(connection)

    assert result.migrated_legacy_schema is True
    organization = connection.execute(
        "SELECT organization_id, organization_name, api_key_hash, created_at, webhook_url "
        "FROM tenant_organizations"
    ).fetchone()
    scan = connection.execute(
        "SELECT scan_id, org_id, created_at, repository_name, commit_sha, finding_count, "
        "deploy_blocking, severity_counts, new_blocking, scan_findings_json "
        "FROM security_scans"
    ).fetchone()
    access_key = connection.execute(
        "SELECT api_key_id, org_id, key_hash, role_code, access_key_label, created_at "
        "FROM access_keys"
    ).fetchone()

    assert tuple(organization) == (
        1,
        "Acme Security",
        "bootstrap-hash-001",
        "2026-08-04T12:00:00Z",
        "https://hooks.example.test/tenant-acme",
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
    assert scan_foreign_key[4] == "organization_id"
    assert key_foreign_key[2] == "tenant_organizations"
    assert key_foreign_key[4] == "organization_id"
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    connection.close()
    reopened = _connection(database_path)
    assert reopened.execute("PRAGMA user_version").fetchone()[0] == 3
    assert reopened.execute("SELECT COUNT(*) FROM security_scans").fetchone()[0] == 1


def test_v2_database_renames_columns_without_data_loss() -> None:
    """Already-canonical v2 databases upgrade in place without dropping rows."""
    connection = _connection()
    connection.executescript(V2_SCHEMA)
    connection.execute(
        "INSERT INTO tenant_organizations(name, api_key_hash, created_at) "
        "VALUES ('Acme Security', 'hash-v2', '2026-08-04T12:00:00Z')"
    )
    connection.execute(
        "INSERT INTO security_scans(org_id, created_at, repo, commit_sha, total, "
        "deploy_blocking, severity_counts, new_blocking, findings) "
        "VALUES (1, '2026-08-04T12:05:00Z', 'ContextualWisdomLab/appguardrail', "
        "'abc123', 1, 1, '{\"HIGH\":1}', 1, '[{\"rule_id\":\"tenant-authz\"}]')"
    )
    connection.execute(
        "INSERT INTO access_keys(org_id, key_hash, role, label, created_at) "
        "VALUES (1, 'key-hash', 'member', 'ci', '2026-08-04T12:06:00Z')"
    )
    connection.execute(
        "INSERT INTO retention_policies(tenant_id, revision, scan_history_days, "
        "audit_event_days, access_key_metadata_days, webhook_metadata_days, "
        "suppression_evidence_days, updated_at, updated_by) "
        "VALUES (1, 4, 30, 365, 90, 30, 90, '2026-08-04T12:07:00Z', 'owner')"
    )
    connection.execute(
        "INSERT INTO legal_holds(legal_hold_id, tenant_id, revision, hold_state, "
        "data_category, subject_type, subject_id, reason, created_at, created_by) "
        "VALUES ('hold-1', 1, 2, 'active', 'scan_history', 'repository', "
        "'ContextualWisdomLab/appguardrail', 'litigation', "
        "'2026-08-04T12:08:00Z', 'owner')"
    )
    connection.commit()

    result = migrate_controlplane_schema(connection)

    assert result.previous_version == 2
    assert result.current_version == 3
    assert connection.execute(
        "SELECT organization_name FROM tenant_organizations WHERE organization_id = 1"
    ).fetchone()[0] == "Acme Security"
    assert connection.execute(
        "SELECT repository_name, finding_count, scan_findings_json "
        "FROM security_scans WHERE scan_id = 1"
    ).fetchone()[0:2] == (
        "ContextualWisdomLab/appguardrail",
        1,
    )
    assert connection.execute(
        "SELECT role_code, access_key_label FROM access_keys WHERE api_key_id = 1"
    ).fetchone()[:] == ("member", "ci")
    assert connection.execute(
        "SELECT policy_revision FROM retention_policies WHERE tenant_id = 1"
    ).fetchone()[0] == 4
    assert connection.execute(
        "SELECT legal_hold_revision, hold_reason FROM legal_holds WHERE legal_hold_id = 'hold-1'"
    ).fetchone()[:] == (2, "litigation")
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert connection.execute(
        "SELECT schema_version, migration_name FROM schema_migrations ORDER BY schema_version"
    ).fetchall() == [(2, "retention_audit_schema_v2"), (3, "semantic_identifier_schema_v3")]


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
    assert second.previous_version == 3
    assert second.current_version == 3
    assert second_schema == first_schema
    assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 1


def test_new_audit_events_are_append_only_at_the_database_boundary() -> None:
    """SQLite itself rejects mutation or deletion of persisted audit evidence."""
    connection = _connection()
    migrate_controlplane_schema(connection)
    connection.execute(
        "INSERT INTO tenant_organizations(organization_name, api_key_hash, created_at) "
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

    for mutation_statement in (
        "UPDATE audit_events SET event_type = 'tampered' "
        "WHERE audit_event_id = 'audit-event-1'",
        "DELETE FROM audit_events WHERE audit_event_id = 'audit-event-1'",
    ):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(mutation_statement)

    assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1


def test_tenant_delete_is_restricted_when_audit_evidence_exists() -> None:
    """Tenant deletion cannot cascade through retained append-only audit evidence."""
    connection = _connection()
    migrate_controlplane_schema(connection)
    connection.execute(
        "INSERT INTO tenant_organizations(organization_name, api_key_hash, created_at) "
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
        connection.execute(
            "DELETE FROM tenant_organizations WHERE organization_id = 1"
        )

    assert connection.execute(
        "SELECT COUNT(*) FROM tenant_organizations WHERE organization_id = 1"
    ).fetchone()[0] == 1
    assert connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE audit_event_id = ?",
        ("audit-event-retained",),
    ).fetchone()[0] == 1
