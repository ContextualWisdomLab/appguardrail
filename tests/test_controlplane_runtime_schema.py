"""Runtime contracts for the canonical embedded control-plane schema."""

from __future__ import annotations

from pathlib import Path

from appguardrail_core.controlplane import add_scan, connect, create_org, get_scan, role_for_key
from appguardrail_core.controlplane_schema import (
    CANONICAL_BASE_TABLE_NAMES,
    LEGACY_TABLE_NAMES,
    inspect_controlplane_schema,
)


def test_connect_initializes_canonical_schema_and_runtime_queries(tmp_path: Path) -> None:
    """A fresh runtime store uses only canonical tables and remains fully usable."""
    connection = connect(str(tmp_path / "control-plane.db"))
    inspection = inspect_controlplane_schema(connection)

    assert CANONICAL_BASE_TABLE_NAMES <= inspection.table_names
    assert LEGACY_TABLE_NAMES.isdisjoint(inspection.table_names)

    tenant_id, api_key = create_org(connection, "Acme Security")
    assert role_for_key(connection, api_key) == (tenant_id, "owner")

    summary = add_scan(
        connection,
        tenant_id,
        [
            {
                "rule_id": "tenant-authz",
                "severity": "HIGH",
                "file": "api/projects.py",
                "line": 41,
                "message": "tenant boundary missing",
                "context": "app-code",
            }
        ],
        repo="ContextualWisdomLab/appguardrail",
        commit_sha="abc123def456",
    )
    stored = get_scan(connection, tenant_id, summary["id"])

    assert stored is not None
    assert stored["repo"] == "ContextualWisdomLab/appguardrail"
    assert stored["findings"][0]["rule_id"] == "tenant-authz"
