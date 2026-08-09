"""Regression tests for webhook URL type validation."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import closing

import pytest

from appguardrail_core.controlplane import (
    _is_safe_url,
    connect,
    create_org,
    make_control_plane_server,
)


def _serve(server: object) -> None:
    """Serve the test control plane in a daemon thread."""
    threading.Thread(target=server.serve_forever, daemon=True).start()


def _req(method: str, url: str, key: str, body: object) -> tuple[int, object]:
    """Send a JSON request to the local test control plane."""
    data = json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {key}")
    request.add_header("Content-Type", "application/json")
    with closing(urllib.request.urlopen(request, timeout=5)) as response:
        return response.status, json.loads(response.read())


@pytest.fixture()
def webhook_server(tmp_path):
    """Start a control plane with a persisted safe webhook baseline."""
    db_path = str(tmp_path / "webhook-types.db")
    conn = connect(db_path)
    org_id, key = create_org(conn, "Acme")
    conn.execute(
        "UPDATE orgs SET webhook_url = ? WHERE id = ?",
        ("http://hook.example/original", org_id),
    )
    conn.commit()
    conn.close()

    server = make_control_plane_server("127.0.0.1", 0, db_path)
    _serve(server)
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}", key, db_path, org_id
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("value", [123, True, {}, []])
def test_is_safe_url_rejects_non_string_values(value: object) -> None:
    """Malformed JSON values must fail closed instead of raising server errors."""
    assert _is_safe_url(value) is False


@pytest.mark.parametrize(
    "body",
    [
        {"url": 123},
        {"url": True},
        {"url": {}},
        [],
        "not-a-mapping",
    ],
)
def test_webhook_endpoint_rejects_malformed_url_types_without_mutation(
    webhook_server, body: object
) -> None:
    """Malformed webhook bodies return 400 and preserve the stored URL."""
    base, key, db_path, org_id = webhook_server

    with pytest.raises(urllib.error.HTTPError) as exc:
        _req("POST", f"{base}/api/v1/webhook", key, body)
    assert exc.value.code == 400

    conn = connect(db_path)
    try:
        stored = conn.execute(
            "SELECT webhook_url FROM orgs WHERE id = ?", (org_id,)
        ).fetchone()["webhook_url"]
    finally:
        conn.close()
    assert stored == "http://hook.example/original"
