"""Regression contracts for the schema shipped before canonical v2 migration."""

from __future__ import annotations

import sqlite3

import pytest

from appguardrail_core.controlplane_schema import migrate_controlplane_schema


SHIPPED_LEGACY_SCHEMA = """
CREATE TABLE orgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    webhook_url TEXT
);
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    repo TEXT,
    commit_sha TEXT,
    total INTEGER NOT NULL,
    deploy_blocking INTEGER NOT NULL,
    severity_counts TEXT NOT NULL,
    new_blocking INTEGER NOT NULL DEFAULT 0,
    findings TEXT NOT NULL,
    FOREIGN KEY (org_id) REFERENCES orgs (id)
);
CREATE INDEX idx_scans_org ON scans (org_id, id DESC);
CREATE TABLE keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'member',
    label TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (org_id) REFERENCES orgs (id)
);
"""


def test_shipped_legacy_access_keys_are_normalized_to_canonical_constraints() -> None:
    """Upgrade must not leave the legacy nullable label or unconstrained role behind."""
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(SHIPPED_LEGACY_SCHEMA)
    connection.execute(
        "INSERT INTO orgs(name, api_key_hash, created_at) VALUES (?, ?, ?)",
        ("Acme Security", "bootstrap-hash", "2026-08-15T00:00:00Z"),
    )
    connection.execute(
        "INSERT INTO keys(org_id, key_hash, role, label, created_at) "
        "VALUES (1, ?, ?, NULL, ?)",
        ("member-hash", "member", "2026-08-15T00:01:00Z"),
    )
    connection.commit()

    result = migrate_controlplane_schema(connection)

    assert result.migrated_legacy_schema is True
    migrated = connection.execute(
        "SELECT role, label FROM access_keys WHERE key_hash = ?", ("member-hash",)
    ).fetchone()
    assert tuple(migrated) == ("member", "")

    columns = {
        row["name"]: row for row in connection.execute("PRAGMA table_info(access_keys)")
    }
    assert columns["label"]["notnull"] == 1

    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO access_keys(org_id, key_hash, role, label, created_at) "
            "VALUES (1, 'invalid-role-hash', 'superuser', 'bad-role', '2026-08-15T00:02:00Z')"
        )
