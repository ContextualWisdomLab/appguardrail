"""Regression contracts for untrusted control-plane values in the console DOM."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import time
import tomllib
from typing import Any
from urllib.parse import urlparse
from urllib.request import ProxyHandler, build_opener

import pytest

from scanner.cli.appguardrail import dashboard_index_path


_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _console_html() -> str:
    """Return the standalone control-plane console document as UTF-8 text."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def _browser_executable() -> str | None:
    """Return an installed Chromium-family executable for the runtime contract."""
    for candidate in (
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ):
        executable = shutil.which(candidate)
        if executable:
            return executable
    return None


def _read_exact(connection: socket.socket, length: int) -> bytes:
    """Read exactly ``length`` bytes from one WebSocket connection."""
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise RuntimeError("DevTools WebSocket closed unexpectedly")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_websocket_frame(
    connection: socket.socket, payload: str | bytes, *, opcode: int = 1
) -> None:
    """Send one masked client WebSocket frame to Chromium DevTools."""
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    first_byte = 0x80 | opcode
    length = len(data)
    if length < 126:
        header = bytes((first_byte, 0x80 | length))
    elif length <= 0xFFFF:
        header = bytes((first_byte, 0x80 | 126)) + struct.pack("!H", length)
    else:
        header = bytes((first_byte, 0x80 | 127)) + struct.pack("!Q", length)
    mask = os.urandom(4)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
    connection.sendall(header + mask + masked)


def _receive_websocket_text(connection: socket.socket) -> str:
    """Receive one complete text message while answering WebSocket pings."""
    fragments: list[bytes] = []
    while True:
        first_byte, second_byte = _read_exact(connection, 2)
        final = bool(first_byte & 0x80)
        opcode = first_byte & 0x0F
        masked = bool(second_byte & 0x80)
        length = second_byte & 0x7F
        if length == 126:
            length = struct.unpack("!H", _read_exact(connection, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", _read_exact(connection, 8))[0]
        mask = _read_exact(connection, 4) if masked else None
        data = _read_exact(connection, length)
        if mask is not None:
            data = bytes(
                value ^ mask[index % 4] for index, value in enumerate(data)
            )
        if opcode == 8:
            raise RuntimeError("Chromium closed the DevTools WebSocket")
        if opcode == 9:
            _send_websocket_frame(connection, data, opcode=10)
            continue
        if opcode in {0, 1}:
            fragments.append(data)
        if final and opcode in {0, 1}:
            return b"".join(fragments).decode("utf-8")


def _connect_devtools_websocket(url: str) -> socket.socket:
    """Open and validate a loopback Chromium DevTools WebSocket connection."""
    parsed = urlparse(url)
    if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("DevTools WebSocket must use loopback ws transport")
    if parsed.port is None:
        raise RuntimeError("DevTools WebSocket URL is missing a port")
    connection = socket.create_connection((parsed.hostname, parsed.port), timeout=10)
    connection.settimeout(10)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}:{parsed.port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    connection.sendall(request.encode("ascii"))
    response = bytearray()
    while not response.endswith(b"\r\n\r\n"):
        response.extend(_read_exact(connection, 1))
        if len(response) > 16_384:
            raise RuntimeError("DevTools WebSocket handshake exceeded 16 KiB")
    header_text = response.decode("iso-8859-1")
    if " 101 " not in header_text.splitlines()[0]:
        raise RuntimeError(f"DevTools WebSocket upgrade failed: {header_text!r}")
    expected = base64.b64encode(
        hashlib.sha1(f"{key}{_WEBSOCKET_GUID}".encode("ascii")).digest()
    ).decode("ascii")
    normalized = header_text.lower()
    if f"sec-websocket-accept: {expected}".lower() not in normalized:
        raise RuntimeError("DevTools WebSocket accept receipt did not match")
    return connection


class _DevToolsSession:
    """Issue bounded Chrome DevTools Protocol calls over one WebSocket."""

    def __init__(self, connection: socket.socket) -> None:
        """Initialize a session with a monotonically increasing request ID."""
        self._connection = connection
        self._request_id = 0

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send one CDP command and return its matching result object."""
        self._request_id += 1
        request_id = self._request_id
        _send_websocket_frame(
            self._connection,
            json.dumps(
                {"id": request_id, "method": method, "params": params or {}},
                separators=(",", ":"),
            ),
        )
        while True:
            message = json.loads(_receive_websocket_text(self._connection))
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise RuntimeError(f"DevTools command {method} failed: {message['error']}")
            result = message.get("result", {})
            if not isinstance(result, dict):
                raise RuntimeError(f"DevTools command {method} returned invalid evidence")
            return result


def _terminate_browser(process: subprocess.Popen[bytes]) -> None:
    """Terminate Chromium and its descendants without leaving a background process."""
    if process.poll() is not None:
        return
    if os.name == "posix":
        os.killpg(process.pid, signal.SIGTERM)
    else:  # pragma: no cover - hosted gate runs on Linux
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - hosted gate runs on Linux
            process.kill()
        process.wait(timeout=5)


def _open_browser_session(
    browser: str, profile: Path
) -> tuple[subprocess.Popen[bytes], socket.socket, _DevToolsSession]:
    """Start Chromium and return its process, WebSocket, and CDP session."""
    process = subprocess.Popen(
        [
            browser,
            "--headless=new",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-dev-shm-usage",
            "--disable-extensions",
            "--disable-gpu",
            "--disable-sync",
            "--metrics-recording-only",
            "--no-first-run",
            "--no-proxy-server",
            "--no-sandbox",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        active_port = profile / "DevToolsActivePort"
        deadline = time.monotonic() + 10
        while not active_port.exists():
            if process.poll() is not None:
                raise RuntimeError(
                    f"Chromium exited before DevTools started ({process.returncode})"
                )
            if time.monotonic() >= deadline:
                raise RuntimeError("Chromium did not publish DevToolsActivePort")
            time.sleep(0.05)
        lines = active_port.read_text(encoding="utf-8").splitlines()
        if len(lines) < 2 or not lines[0].isdigit():
            raise RuntimeError("Chromium published malformed DevToolsActivePort")
        port = int(lines[0])
        opener = build_opener(ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/json/list", timeout=10) as response:
            targets = json.load(response)
        if not isinstance(targets, list):
            raise RuntimeError("Chromium target list was not an array")
        pages = [target for target in targets if target.get("type") == "page"]
        if len(pages) != 1 or not isinstance(pages[0].get("webSocketDebuggerUrl"), str):
            raise RuntimeError("Chromium did not expose exactly one page target")
        connection = _connect_devtools_websocket(pages[0]["webSocketDebuggerUrl"])
        return process, connection, _DevToolsSession(connection)
    except Exception:
        _terminate_browser(process)
        raise


def test_console_escapes_every_untrusted_inner_html_value() -> None:
    """Keep untrusted summary, trend, history, and detail values behind ``esc``."""
    html = _console_html()

    required_escaped_fragments = {
        '${esc(l)}',
        '${esc(n)}',
        'style="background:${color}">${esc(n)}</span>',
        'data-id="${esc(s.id)}"',
        '<td>${esc(s.total)}</td>',
        '${esc(s.created_at)}',
        '${esc(String(s.deploy_blocking||0))}',
        '${esc(s.repo||"—")}',
        '${esc((s.commit||"—").slice(0,10))}',
        '${esc(f.severity)}',
        '${esc(f.rule_id)}',
        '${esc((f.message||"").split("\\n")[0].slice(0,120))}',
        '${esc(f.file)}:${esc(f.line)}',
        'Scan #${esc(s.id)}',
    }
    for fragment in required_escaped_fragments:
        assert fragment in html

    forbidden_raw_fragments = {
        '<div class="l">${l}</div>',
        '<div class="n">${n}</div>',
        'style="background:${color}">${n}</span>',
        'data-id="${s.id}"',
        '<td>${s.total}</td>',
    }
    for fragment in forbidden_raw_fragments:
        assert fragment not in html


def test_console_runtime_regression_does_not_ship_browser_automation_dependency() -> None:
    """Use the runner browser without expanding AppGuardrail's runtime dependency set."""
    repository_root = Path(__file__).resolve().parents[1]
    project = tomllib.loads(
        (repository_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    dependencies = project.get("project", {}).get("dependencies", [])

    assert not any(
        isinstance(dependency, str) and dependency.lower().startswith("playwright")
        for dependency in dependencies
    ), "Playwright is test tooling, not an AppGuardrail runtime dependency"


def test_console_xss_regression_does_not_commit_runtime_report_fixture() -> None:
    """Keep generated findings out of the standard repository report path."""
    repository_root = Path(__file__).resolve().parents[1]

    assert not (repository_root / "reports" / "findings.json").exists()


def test_console_executes_hostile_scan_values_as_inert_text(tmp_path: Path) -> None:
    """Render hostile summary, trend, history, and detail values without DOM XSS."""
    browser = _browser_executable()
    if browser is None:
        if os.environ.get("CI"):
            pytest.fail("CI must provide Chrome or Chromium for the DOM XSS gate")
        pytest.skip("Chrome or Chromium is not installed")

    image_attack = (
        '<img src=x onerror="document.documentElement.dataset.imageXss=\'1\'">'
    )
    script_attack = (
        "<script>document.documentElement.dataset.scriptXss='1'</script>"
    )
    image_literal = json.dumps(image_attack).replace("</", "<\\/")
    script_literal = json.dumps(script_attack).replace("</", "<\\/")
    harness = f"""
const imageAttack={image_literal};
const scriptAttack={script_literal};
const pillAttack={{
  valueOf(){{return 1;}},
  toString(){{return imageAttack;}},
}};
const scan={{
  id:imageAttack,
  created_at:scriptAttack,
  repo:imageAttack,
  commit:scriptAttack,
  total:imageAttack,
  deploy_blocking:pillAttack,
  new_blocking:pillAttack,
  severity_counts:{{CRITICAL:pillAttack}},
}};
window.fetch=async path=>({{
  status:200,
  ok:true,
  json:async()=>String(path).startsWith("/api/v1/scans/")
    ? {{
        id:scriptAttack,
        created_at:imageAttack,
        repo:scriptAttack,
        findings:[{{
          severity:imageAttack,
          rule_id:scriptAttack,
          message:imageAttack,
          file:scriptAttack,
          line:imageAttack,
        }}],
      }}
    : {{scans:[scan]}},
}});
KEY="agk_runtime_contract";
Promise.resolve()
  .then(load)
  .then(()=>{{
    const row=document.querySelector("tr.scan");
    if(!row)throw new Error("scan row was not rendered");
    return detail(scan.id,row);
  }})
  .then(()=>new Promise(resolve=>setTimeout(resolve,50)))
  .then(()=>{{
    const root=document.documentElement;
    const trend=document.querySelector("#trend .bar");
    root.dataset.imageElementCount=String(document.querySelectorAll("img").length);
    root.dataset.scriptElementCount=String(document.querySelectorAll("script").length);
    root.dataset.pillText=Array.from(document.querySelectorAll("#history .pill"))
      .map(element=>element.textContent).join("|");
    root.dataset.trendLabel=trend?trend.getAttribute("aria-label")||"":"";
    root.dataset.testComplete="1";
  }})
  .catch(error=>{{
    document.documentElement.dataset.testError=String(error&&error.message||error);
    document.documentElement.dataset.testComplete="1";
  }});
"""
    console = _console_html()
    fixture = console.replace("if(KEY)load();", harness)
    assert fixture != console

    process: subprocess.Popen[bytes] | None = None
    connection: socket.socket | None = None
    try:
        process, connection, session = _open_browser_session(
            browser, tmp_path / "chromium-profile"
        )
        session.call("Page.enable")
        session.call("Runtime.enable")
        frame_tree = session.call("Page.getFrameTree")
        frame_id = frame_tree.get("frameTree", {}).get("frame", {}).get("id")
        if not isinstance(frame_id, str) or not frame_id:
            raise RuntimeError("Chromium did not expose a root frame ID")
        session.call("Page.setDocumentContent", {"frameId": frame_id, "html": fixture})

        deadline = time.monotonic() + 10
        while True:
            result = session.call(
                "Runtime.evaluate",
                {
                    "expression": (
                        'document.documentElement.dataset.testComplete||""'
                    ),
                    "returnByValue": True,
                },
            )
            value = result.get("result", {}).get("value")
            if value == "1":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("console runtime contract did not complete")
            time.sleep(0.05)

        evidence_result = session.call(
            "Runtime.evaluate",
            {
                "expression": """JSON.stringify({
  testComplete:document.documentElement.dataset.testComplete||null,
  testError:document.documentElement.dataset.testError||null,
  imageXss:document.documentElement.dataset.imageXss||null,
  scriptXss:document.documentElement.dataset.scriptXss||null,
  imageCount:document.querySelectorAll("img").length,
  scriptCount:document.querySelectorAll("script").length,
  pillText:document.documentElement.dataset.pillText||null,
  trendLabel:document.documentElement.dataset.trendLabel||null
})""",
                "returnByValue": True,
            },
        )
        encoded = evidence_result.get("result", {}).get("value")
        if not isinstance(encoded, str):
            raise RuntimeError("Chromium did not return serialized DOM evidence")
        evidence = json.loads(encoded)
    finally:
        if connection is not None:
            connection.close()
        if process is not None:
            _terminate_browser(process)

    assert evidence["testComplete"] == "1"
    assert evidence["testError"] is None
    assert evidence["imageXss"] is None
    assert evidence["scriptXss"] is None
    assert evidence["imageCount"] == 0
    assert evidence["scriptCount"] == 1
    assert image_attack in evidence["pillText"]
    assert script_attack in evidence["trendLabel"]
    assert image_attack in evidence["trendLabel"]
