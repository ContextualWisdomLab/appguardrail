"""Security regressions for the browser console's least-privilege key contract."""

import threading
import urllib.error
import urllib.request

import pytest

from appguardrail_core.controlplane import connect, create_key, create_org, make_control_plane_server
from scanner.cli.appguardrail import dashboard_index_path


def _empty_scan_post_status(url: str, api_key: str) -> int:
    """Return the status of a bodyless scan POST used only as an authz probe."""
    request = urllib.request.Request(url, data=b"", method="POST")
    request.add_header("Authorization", f"Bearer {api_key}")
    try:
        urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        return error.code
    raise AssertionError("bodyless scan POST unexpectedly succeeded")


@pytest.fixture()
def viewer_role_server(tmp_path):
    """Serve a control plane with distinct viewer, member, and owner credentials."""
    db_path = str(tmp_path / "viewer-role.db")
    connection = connect(db_path)
    org_id, owner_key = create_org(connection, "Acme")
    _viewer_id, viewer_key = create_key(connection, org_id, "viewer", "browser console")
    _member_id, member_key = create_key(connection, org_id, "member", "ci ingest")
    connection.close()

    server = make_control_plane_server("127.0.0.1", 0, db_path)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}", owner_key, member_key, viewer_key
    finally:
        server.shutdown()
        server.server_close()


def test_bodyless_scan_post_distinguishes_viewer_from_elevated_roles(
    viewer_role_server,
) -> None:
    """A side-effect-free malformed POST must distinguish viewer from write roles."""
    base, owner_key, member_key, viewer_key = viewer_role_server
    endpoint = f"{base}/api/v1/scans"

    assert _empty_scan_post_status(endpoint, viewer_key) == 403
    assert _empty_scan_post_status(endpoint, member_key) == 400
    assert _empty_scan_post_status(endpoint, owner_key) == 400


def test_console_accepts_only_viewer_keys_and_never_persists_credentials() -> None:
    """The browser console must reject elevated keys and keep viewer keys in memory."""
    html = dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")

    assert 'placeholder="Viewer API key (agk_…)"' in html
    assert 'aria-label="Viewer API key"' in html
    assert 'sessionStorage.removeItem("ag_key");' in html
    assert 'sessionStorage.removeItem("ag_viewer_key");' in html
    assert "sessionStorage.setItem" not in html
    assert "sessionStorage.getItem" not in html

    assert "async function requireViewerKey()" in html
    viewer_probe = 'fetch("/api/v1/scans",{method:"POST",headers:{Authorization:"Bearer "+KEY}})'
    reject_elevated = 'if(r.status!==403)throw new Error("Use a dedicated viewer API key.");'
    assert viewer_probe in html
    assert reject_elevated in html

    connect_flow = html.split('$("#connect").onclick=', 1)[1].split(
        '$("#key").addEventListener', 1
    )[0]
    assert "await requireViewerKey();" in connect_flow
    assert "await load();" in connect_flow
    assert connect_flow.index("await requireViewerKey();") < connect_flow.index("await load();")
