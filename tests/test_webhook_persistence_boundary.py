"""Regression tests for the stored-webhook admission boundary."""

import json
import threading
import urllib.error
import urllib.request
from contextlib import closing

import pytest

from appguardrail_core.controlplane import (
    connect,
    create_org,
    make_control_plane_server,
    set_webhook,
)


_PUBLIC_WEBHOOK = "https://8.8.8.8/alert"


def _stored_webhook(conn, org_id: int):
    """Return the current persisted webhook for one organization."""
    return conn.execute(
        "SELECT webhook_url FROM orgs WHERE id = ?", (org_id,)
    ).fetchone()[0]


def _serve(server) -> None:
    """Start one test control-plane server."""
    threading.Thread(target=server.serve_forever, daemon=True).start()


def _request(method, url, key=None, body=None):
    """Send one JSON test request and decode its response."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if key:
        request.add_header("Authorization", f"Bearer {key}")
    if data:
        request.add_header("Content-Type", "application/json")
    with closing(urllib.request.urlopen(request, timeout=5)) as response:
        return response.status, json.loads(response.read())


@pytest.fixture()
def webhook_server(tmp_path):
    """Yield an isolated control-plane server and owner key."""
    db_path = str(tmp_path / "controlplane.db")
    conn = connect(db_path)
    _, key = create_org(conn, "Acme")
    conn.close()
    server = make_control_plane_server("127.0.0.1", 0, db_path)
    _serve(server)
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", key
    finally:
        server.shutdown()
        server.server_close()


def test_set_webhook_rejects_unsafe_destination_before_persistence():
    """Direct callers cannot persist an internal destination."""
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")

    with pytest.raises(ValueError, match="invalid webhook url"):
        set_webhook(conn, org_id, "http://127.0.0.1/internal")

    assert _stored_webhook(conn, org_id) is None


@pytest.mark.parametrize("url", ["http://", "https://", "http://user@"])
def test_set_webhook_rejects_empty_hostname_before_persistence(url):
    """Malformed HTTP(S) authorities fail before the database write."""
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")

    with pytest.raises(ValueError, match="invalid webhook url"):
        set_webhook(conn, org_id, url)

    assert _stored_webhook(conn, org_id) is None


def test_set_webhook_rejects_non_string_before_sqlite_binding():
    """Non-string JSON values become a domain error, not a SQLite exception."""
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")

    with pytest.raises(ValueError, match="invalid webhook url"):
        set_webhook(conn, org_id, 1234)  # type: ignore[arg-type]

    assert _stored_webhook(conn, org_id) is None


@pytest.mark.parametrize("cleared_value", ["", None])
def test_set_webhook_explicit_clear_preserves_contract(cleared_value):
    """Explicit empty-string and null inputs clear an existing webhook."""
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")
    set_webhook(conn, org_id, _PUBLIC_WEBHOOK)
    assert _stored_webhook(conn, org_id) == _PUBLIC_WEBHOOK

    set_webhook(conn, org_id, cleared_value)

    assert _stored_webhook(conn, org_id) is None


def test_api_missing_url_is_rejected_without_clearing(webhook_server):
    """An omitted field is not interpreted as an explicit clear request."""
    base_url, key = webhook_server
    status, _ = _request(
        "POST", f"{base_url}/api/v1/webhook", key, {"url": _PUBLIC_WEBHOOK}
    )
    assert status == 200

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _request("POST", f"{base_url}/api/v1/webhook", key, {})

    assert exc_info.value.code == 400
    assert json.loads(exc_info.value.read()) == {"error": "url is required"}


def test_api_explicit_null_clears_existing_destination(webhook_server):
    """A present null field remains the API's explicit deletion command."""
    base_url, key = webhook_server
    _request("POST", f"{base_url}/api/v1/webhook", key, {"url": _PUBLIC_WEBHOOK})

    status, body = _request(
        "POST", f"{base_url}/api/v1/webhook", key, {"url": None}
    )

    assert status == 200
    assert body["webhook_url"] is None


@pytest.mark.parametrize("url", ["http://", "https://", "http://user@"])
def test_api_rejects_empty_hostname(webhook_server, url):
    """The HTTP API returns a bounded domain error for empty authorities."""
    base_url, key = webhook_server

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _request("POST", f"{base_url}/api/v1/webhook", key, {"url": url})

    assert exc_info.value.code == 400
    assert json.loads(exc_info.value.read()) == {"error": "invalid webhook url"}
