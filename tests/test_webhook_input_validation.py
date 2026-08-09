"""Regression tests for fail-closed webhook request-body validation."""

import json
import threading
import urllib.error
import urllib.request
from contextlib import closing

import pytest

from appguardrail_core.controlplane import connect, create_org, make_control_plane_server

_BASELINE_URL = "http://hook.example/existing"


def _serve(server):
    """Start the isolated control-plane server on a daemon thread."""
    threading.Thread(target=server.serve_forever, daemon=True).start()


@pytest.fixture()
def webhook_server(tmp_path):
    """Serve an isolated control plane and expose its URL, owner key, and DB."""
    db = str(tmp_path / "webhook-validation.db")
    conn = connect(db)
    _org_id, key = create_org(conn, "Webhook validation")
    conn.close()
    server = make_control_plane_server("127.0.0.1", 0, db)
    _serve(server)
    port = server.server_address[1]
    yield f"http://127.0.0.1:{port}", key, db
    server.shutdown()
    server.server_close()


def _post(base, key, body):
    """POST one JSON value to the webhook configuration endpoint."""
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{base}/api/v1/webhook",
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
    )
    with closing(urllib.request.urlopen(request, timeout=5)) as response:
        return response.status, json.loads(response.read())


def _stored_webhook(db):
    """Read the currently persisted webhook URL from the isolated database."""
    conn = connect(db)
    try:
        row = conn.execute("SELECT webhook_url FROM orgs LIMIT 1").fetchone()
        return row["webhook_url"]
    finally:
        conn.close()


def _seed_existing_webhook(base, key, db):
    """Persist and verify a safe baseline URL before rejection tests."""
    status, payload = _post(base, key, {"url": _BASELINE_URL})
    assert status == 200
    assert payload == {"webhook_url": _BASELINE_URL}
    assert _stored_webhook(db) == _BASELINE_URL


@pytest.mark.parametrize("body", [[], "url", 7, True])
def test_webhook_rejects_non_object_json_bodies(webhook_server, body):
    """Non-object JSON is rejected without replacing an existing webhook."""
    base, key, db = webhook_server
    _seed_existing_webhook(base, key, db)
    with pytest.raises(urllib.error.HTTPError) as error:
        _post(base, key, body)
    assert error.value.code == 400
    assert json.loads(error.value.read()) == {"error": "invalid JSON body"}
    assert _stored_webhook(db) == _BASELINE_URL


@pytest.mark.parametrize("url", [7, True, [], {}])
def test_webhook_rejects_non_string_url_values(webhook_server, url):
    """Non-string URL values fail before persistence and preserve prior state."""
    base, key, db = webhook_server
    _seed_existing_webhook(base, key, db)
    with pytest.raises(urllib.error.HTTPError) as error:
        _post(base, key, {"url": url})
    assert error.value.code == 400
    assert json.loads(error.value.read()) == {"error": "unsafe webhook url"}
    assert _stored_webhook(db) == _BASELINE_URL


@pytest.mark.parametrize("url", [None, ""])
def test_webhook_preserves_explicit_clear_values(webhook_server, url):
    """Null and empty-string inputs remain supported as webhook clear requests."""
    base, key, db = webhook_server
    _seed_existing_webhook(base, key, db)
    status, payload = _post(base, key, {"url": url})
    assert status == 200
    assert payload == {"webhook_url": url}
    assert _stored_webhook(db) is None
