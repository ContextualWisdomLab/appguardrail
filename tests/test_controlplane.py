"""Tests for the multi-tenant control-plane store + API."""

import json
import threading
import urllib.error
import urllib.request
from contextlib import closing

import pytest

from appguardrail_core.controlplane import (
    add_scan,
    connect,
    create_org,
    get_scan,
    list_scans,
    make_control_plane_server,
    org_for_key,
)

FINDINGS = [
    {"severity": "CRITICAL", "rule_id": "x", "context": "app-code"},
    {"severity": "INFO", "rule_id": "y", "context": "doc"},
]


# ---- store ----

def test_org_key_auth():
    conn = connect(":memory:")
    oid, key = create_org(conn, "Acme")
    assert org_for_key(conn, key) == oid
    assert org_for_key(conn, "agk_wrong") is None
    assert org_for_key(conn, "") is None


def test_add_and_list_scan_counts():
    conn = connect(":memory:")
    oid, _ = create_org(conn, "Acme")
    s = add_scan(conn, oid, FINDINGS, repo="acme/app", commit_sha="abc")
    assert s["total"] == 2 and s["deploy_blocking"] == 1
    listed = list_scans(conn, oid)
    assert len(listed) == 1 and listed[0]["repo"] == "acme/app"
    full = get_scan(conn, oid, s["id"])
    assert len(full["findings"]) == 2


def test_tenant_isolation():
    conn = connect(":memory:")
    a, _ = create_org(conn, "Acme")
    b, _ = create_org(conn, "Beta")
    s = add_scan(conn, a, FINDINGS)
    assert get_scan(conn, b, s["id"]) is None  # cross-tenant read blocked
    assert list_scans(conn, b) == []


# ---- API ----

def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()


def _req(method, url, key=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if key:
        r.add_header("Authorization", f"Bearer {key}")
    if data:
        r.add_header("Content-Type", "application/json")
    with closing(urllib.request.urlopen(r, timeout=5)) as resp:
        return resp.status, json.loads(resp.read())


@pytest.fixture()
def server(tmp_path):
    db = str(tmp_path / "cp.db")
    conn = connect(db)
    _oid, key = create_org(conn, "Acme")
    conn.close()
    srv = make_control_plane_server("127.0.0.1", 0, db)
    _serve(srv)
    port = srv.server_address[1]
    yield f"http://127.0.0.1:{port}", key
    srv.shutdown()
    srv.server_close()


def test_health_no_auth(server):
    base, _ = server
    status, body = _req("GET", f"{base}/api/v1/health")
    assert status == 200 and body["status"] == "ok"


def test_ingest_and_history(server):
    base, key = server
    status, summary = _req(
        "POST", f"{base}/api/v1/scans", key,
        {"repo": "acme/app", "commit": "abc", "findings": FINDINGS},
    )
    assert status == 201 and summary["deploy_blocking"] == 1
    status, listing = _req("GET", f"{base}/api/v1/scans", key)
    assert status == 200 and len(listing["scans"]) == 1
    scan_id = listing["scans"][0]["id"]
    status, full = _req("GET", f"{base}/api/v1/scans/{scan_id}", key)
    assert status == 200 and len(full["findings"]) == 2


def test_auth_required(server):
    base, _ = server
    for key in (None, "agk_wrong"):
        with pytest.raises(urllib.error.HTTPError) as exc:
            _req("GET", f"{base}/api/v1/scans", key)
        assert exc.value.code == 401


def test_bad_body_400(server):
    base, key = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _req("POST", f"{base}/api/v1/scans", key, {"findings": "not-a-list"})
    assert exc.value.code == 400


def test_console_served_at_root(server):
    base, _ = server
    with closing(urllib.request.urlopen(base + "/", timeout=5)) as resp:
        body = resp.read()
    assert resp.status == 200
    assert b"AppGuardrail Console" in body  # served the org console HTML
