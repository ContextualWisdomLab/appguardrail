"""Regression coverage for the control-plane webhook persistence boundary."""

import pytest

from appguardrail_core.controlplane import connect, create_org, set_webhook


def _stored_webhook(conn, org_id: int):
    row = conn.execute(
        "SELECT webhook_url FROM orgs WHERE id = ?", (org_id,)
    ).fetchone()
    assert row is not None
    return row["webhook_url"]


def test_set_webhook_rejects_unsafe_values_before_persistence():
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")
    safe_url = "https://1.1.1.1/hook"
    set_webhook(conn, org_id, safe_url)
    assert _stored_webhook(conn, org_id) == safe_url

    for unsafe_url in (
        "http://127.0.0.1/hook",
        "file:///tmp/hook",
        1234,
    ):
        with pytest.raises(ValueError, match="invalid webhook url"):
            set_webhook(conn, org_id, unsafe_url)
        assert _stored_webhook(conn, org_id) == safe_url


def test_set_webhook_clear_remains_null_persistence():
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")
    set_webhook(conn, org_id, "https://1.1.1.1/hook")

    set_webhook(conn, org_id, None)

    assert _stored_webhook(conn, org_id) is None
