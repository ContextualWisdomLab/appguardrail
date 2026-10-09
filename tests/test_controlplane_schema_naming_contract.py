"""Regression coverage for semantic control-plane persistence identifiers."""

import sqlite3

from appguardrail_core import controlplane_schema as schema


def test_canonical_database_columns_use_bounded_context_names() -> None:
    """Reject generic one-word identifiers in organization-owned SQLite tables."""
    connection = sqlite3.connect(":memory:")
    schema.migrate_controlplane_schema(connection)
    inspection = schema.inspect_controlplane_schema(connection)

    expected_columns = {
        "tenant_organizations": {
            "organization_id",
            "organization_name",
            "api_key_hash",
            "created_at",
            "webhook_url",
        },
        "security_scans": {
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
        },
        "access_keys": {
            "api_key_id",
            "org_id",
            "key_hash",
            "role_code",
            "access_key_label",
            "created_at",
        },
        "retention_policies": {
            "tenant_id",
            "policy_revision",
            "scan_history_days",
            "audit_event_days",
            "access_key_metadata_days",
            "webhook_metadata_days",
            "suppression_evidence_days",
            "updated_at",
            "updated_by",
        },
        "legal_holds": {
            "legal_hold_id",
            "tenant_id",
            "legal_hold_revision",
            "hold_state",
            "data_category",
            "subject_type",
            "subject_id",
            "hold_reason",
            "created_at",
            "created_by",
            "released_at",
            "released_by",
        },
    }

    for table_name, semantic_columns in expected_columns.items():
        assert inspection.table_columns[table_name] == frozenset(semantic_columns)

    forbidden_columns = {
        "tenant_organizations": {"id", "name"},
        "security_scans": {"id", "repo", "total", "findings"},
        "access_keys": {"id", "role", "label"},
        "retention_policies": {"revision"},
        "legal_holds": {"revision", "reason"},
    }
    for table_name, generic_columns in forbidden_columns.items():
        assert inspection.table_columns[table_name].isdisjoint(generic_columns)


def test_semantic_foreign_keys_reference_semantic_parent_identifiers() -> None:
    """Keep renamed parent keys and dependent foreign keys consistent."""
    connection = sqlite3.connect(":memory:")
    schema.migrate_controlplane_schema(connection)

    scan_foreign_key = connection.execute(
        "PRAGMA foreign_key_list(security_scans)"
    ).fetchone()
    key_foreign_key = connection.execute(
        "PRAGMA foreign_key_list(access_keys)"
    ).fetchone()

    assert scan_foreign_key[2] == "tenant_organizations"
    assert scan_foreign_key[4] == "organization_id"
    assert key_foreign_key[2] == "tenant_organizations"
    assert key_foreign_key[4] == "organization_id"
