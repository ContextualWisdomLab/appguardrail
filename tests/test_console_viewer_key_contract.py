"""Security regressions for the browser console's least-privilege key contract."""

import json
import threading
import urllib.request
from contextlib import closing

import pytest

from appguardrail_core.controlplane import connect, create_key, create_org, make_control_plane_server
from scanner.cli.appguardrail import dashboard_index_path


def _request_json(url: str, api_key: str) -> tuple[int, dict[str, str]]:
    """GET one authenticated JSON endpoint using the supplied API key."""
    request = urllib.request.Request(url, method="GET")
    request.add_header("Authorization", f"Bearer {api_key}")
    with closing(urllib.request.urlopen(request, timeout=5)) as response:
        return response.status, json.loads(response.read())


@pytest.fixture()
def viewer_role_server(tmp_path):
    """Serve a control plane with distinct owner and viewer credentials."""
    db_path = str(tmp_path / "viewer-role.db")
    connection = connect(db_path)
    org_id, owner_key = create_org(connection, "Acme")
    _key_id, viewer_key = create_key(connection, org_id, "viewer", "browser console")
    connection.close()

    server = make_control_plane_server("127.0.0.1", 0, db_path)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}", owner_key, viewer_key
    finally:
        server.shutdown()
        server.server_close()


def test_session_endpoint_reports_authenticated_role(viewer_role_server) -> None:
    """The console must be able to distinguish viewer keys from elevated keys."""
    base, owner_key, viewer_key = viewer_role_server

    assert _request_json(f"{base}/api/v1/session", viewer_key) == (
        200,
        {"role": "viewer"},
    )
    assert _request_json(f"{base}/api/v1/session", owner_key) == (
        200,
        {"role": "owner"},
    )


def test_console_persists_only_validated_viewer_keys() -> None:
    """Browser storage must never retain an owner or member API key."""
    html = (
        dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")
    )

    assert 'placeholder="Viewer API key (agk_…)"' in html
    assert 'aria-label="Viewer API key"' in html
    assert 'sessionStorage.removeItem("ag_key");' in html
    assert 'sessionStorage.getItem("ag_viewer_key")' in html

    connect_flow = html.split('$("#connect").onclick=', 1)[1].split(
        '$("#key").addEventListener', 1
    )[0]
    role_check = 'const session=await api("/api/v1/session");'
    reject_elevated = 'if(session.role!=="viewer")throw new Error("Use a dedicated viewer API key.");'
    persist_viewer = 'sessionStorage.setItem("ag_viewer_key",KEY);'

    assert role_check in connect_flow
    assert reject_elevated in connect_flow
    assert persist_viewer in connect_flow
    assert connect_flow.index(role_check) < connect_flow.index(reject_elevated)
    assert connect_flow.index(reject_elevated) < connect_flow.index(persist_viewer)
