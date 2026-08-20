"""Rendered-browser regression for the organization console DOM XSS boundary."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time
from typing import Any, Iterator
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import pytest

from scanner.cli.appguardrail import dashboard_index_path


_IMAGE_PAYLOAD = (
    '<img id="xss-image" src="x" '
    'onerror="document.body.dataset.xssExecuted=\'1\'">'
)
_SCRIPT_PAYLOAD = (
    '<script id="xss-script">'
    "document.body.dataset.xssExecuted='1'"
    "</script>"
)
_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _encoded_fixture(payload: object) -> str:
    """Return one finite JSON fixture as browser-safe base64 text."""
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _instrumented_console() -> str:
    """Return the shipped console with deterministic in-page API fixtures."""
    source = (
        dashboard_index_path()
        .with_name("console.html")
        .read_text(encoding="utf-8")
    )
    key_boundary = 'let KEY=sessionStorage.getItem("ag_key")||"";'
    assert source.count(key_boundary) == 1
    source = source.replace(key_boundary, 'let KEY="";', 1)

    list_fixture = _encoded_fixture(
        {
            "scans": [
                {
                    "id": "scan-1",
                    "created_at": _SCRIPT_PAYLOAD,
                    "repo": _IMAGE_PAYLOAD,
                    "commit": _SCRIPT_PAYLOAD,
                    "total": _IMAGE_PAYLOAD,
                    "deploy_blocking": 1,
                    "new_blocking": 1,
                    "severity_counts": {"CRITICAL": _SCRIPT_PAYLOAD},
                }
            ]
        }
    )
    detail_fixture = _encoded_fixture(
        {
            "id": _IMAGE_PAYLOAD,
            "created_at": _SCRIPT_PAYLOAD,
            "repo": _IMAGE_PAYLOAD,
            "findings": [
                {
                    "severity": "CRITICAL",
                    "rule_id": _IMAGE_PAYLOAD,
                    "message": _SCRIPT_PAYLOAD,
                    "file": _IMAGE_PAYLOAD,
                    "line": _SCRIPT_PAYLOAD,
                }
            ],
        }
    )
    api_start = source.index("async function api(path){")
    api_end = source.index("\nfunction pill", api_start)
    fixture_api = f'''const __LIST_FIXTURE=JSON.parse(atob("{list_fixture}"));
const __DETAIL_FIXTURE=JSON.parse(atob("{detail_fixture}"));
async function api(path){{
  if(path==="/api/v1/scans")return __LIST_FIXTURE;
  if(path.startsWith("/api/v1/scans/"))return __DETAIL_FIXTURE;
  throw new Error("Unexpected fixture path: "+path);
}}'''
    source = source[:api_start] + fixture_api + source[api_end:]

    marker = "if(KEY)load();"
    driver = """(async()=>{
  KEY="agk_rendered_browser_regression";
  await load();
  const row=document.querySelector("tr.scan");
  if(!row){document.body.dataset.testFailure="missing-scan-row";return;}
  await detail(row.dataset.id,row);
  document.body.dataset.testDone="1";
})();"""
    assert source.count(marker) == 1
    return source.replace(marker, driver, 1)


class _DevToolsWebSocket:
    """Minimal bounded WebSocket client for local Chrome DevTools Protocol."""

    def __init__(self, websocket_url: str) -> None:
        parsed = urlsplit(websocket_url)
        if (
            parsed.scheme != "ws"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.port is None
        ):
            raise ValueError("Chrome DevTools URL must be a local ws endpoint")
        self._socket = socket.create_connection(
            (parsed.hostname, parsed.port),
            timeout=10,
        )
        self._buffer = b""
        self._next_id = 1
        self._handshake(parsed.path or "/", parsed.query, parsed.port)

    def _handshake(self, path: str, query: str, port: int) -> None:
        """Complete and authenticate the RFC 6455 upgrade response."""
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        target = path + (f"?{query}" if query else "")
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        self._socket.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise ConnectionError("Chrome closed during WebSocket handshake")
            response += chunk
            if len(response) > 65536:
                raise ValueError("Chrome WebSocket handshake exceeded 64 KiB")
        raw_headers, self._buffer = response.split(b"\r\n\r\n", 1)
        lines = raw_headers.decode("latin-1").split("\r\n")
        if not lines or " 101 " not in lines[0]:
            raise ConnectionError(f"Chrome rejected WebSocket upgrade: {lines[0]}")
        headers = {
            name.strip().lower(): value.strip()
            for line in lines[1:]
            if ":" in line
            for name, value in [line.split(":", 1)]
        }
        expected = base64.b64encode(
            hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()
        ).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            raise ConnectionError("Chrome WebSocket accept receipt did not match")

    def _read_exact(self, size: int) -> bytes:
        """Read exactly ``size`` bytes from the buffered socket."""
        while len(self._buffer) < size:
            chunk = self._socket.recv(65536)
            if not chunk:
                raise ConnectionError("Chrome closed the DevTools socket")
            self._buffer += chunk
        value, self._buffer = self._buffer[:size], self._buffer[size:]
        return value

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        """Send one masked client frame with a finite payload."""
        if len(payload) > 16 * 1024 * 1024:
            raise ValueError("DevTools message exceeds the 16 MiB test bound")
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.extend((0x80 | 126,))
            header.extend(struct.pack("!H", length))
        else:
            header.extend((0x80 | 127,))
            header.extend(struct.pack("!Q", length))
        mask = os.urandom(4)
        header.extend(mask)
        header.extend(
            byte ^ mask[index % 4]
            for index, byte in enumerate(payload)
        )
        self._socket.sendall(header)

    def _receive_json(self) -> dict[str, Any]:
        """Receive one complete text message while handling ping frames."""
        fragments: list[bytes] = []
        message_opcode: int | None = None
        while True:
            first, second = self._read_exact(2)
            finished = bool(first & 0x80)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            if length > 16 * 1024 * 1024:
                raise ValueError("Chrome DevTools frame exceeds 16 MiB")
            mask = self._read_exact(4) if second & 0x80 else None
            payload = self._read_exact(length)
            if mask is not None:
                payload = bytes(
                    byte ^ mask[index % 4]
                    for index, byte in enumerate(payload)
                )
            if opcode == 0x09:
                self._send_frame(0x0A, payload)
                continue
            if opcode == 0x08:
                raise ConnectionError("Chrome closed the DevTools WebSocket")
            if opcode in {0x01, 0x02}:
                message_opcode = opcode
                fragments = [payload]
            elif opcode == 0x00 and message_opcode is not None:
                fragments.append(payload)
            else:
                continue
            if not finished:
                continue
            if message_opcode != 0x01:
                raise ValueError("Expected a text DevTools message")
            parsed = json.loads(b"".join(fragments).decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("Chrome DevTools response must be an object")
            return parsed

    def call(
        self,
        method: str,
        parameters: dict[str, Any] | None = None,
        *,
        timeout: float = 15,
    ) -> dict[str, Any]:
        """Invoke one CDP method and return its matching response object."""
        call_id = self._next_id
        self._next_id += 1
        request = {
            "id": call_id,
            "method": method,
            "params": parameters or {},
        }
        self._send_frame(
            0x01,
            json.dumps(request, separators=(",", ":")).encode("utf-8"),
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._socket.settimeout(max(0.1, deadline - time.monotonic()))
            response = self._receive_json()
            if response.get("id") != call_id:
                continue
            if "error" in response:
                raise RuntimeError(f"Chrome DevTools error: {response['error']}")
            result = response.get("result", {})
            if not isinstance(result, dict):
                raise ValueError("Chrome DevTools result must be an object")
            return result
        raise TimeoutError(f"Chrome DevTools call timed out: {method}")

    def close(self) -> None:
        """Close the local DevTools socket without retaining browser state."""
        try:
            self._send_frame(0x08, b"")
        except (OSError, ValueError):
            pass
        self._socket.close()


def _chrome_path() -> Path:
    """Return the workflow-provisioned Chrome executable or skip locally."""
    value = os.environ.get("APPGUARDRAIL_CHROME_PATH")
    if not value:
        pytest.skip("rendered-browser lane provides APPGUARDRAIL_CHROME_PATH")
    path = Path(value)
    assert path.is_file(), f"Chrome executable does not exist: {path}"
    return path


def _wait_for_debug_port(
    profile: Path,
    process: subprocess.Popen[bytes],
    stderr_path: Path,
) -> int:
    """Read Chrome's bounded local debugging-port receipt."""
    receipt = profile / "DevToolsActivePort"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            diagnostics = stderr_path.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(f"Chrome exited before DevTools startup:\n{diagnostics}")
        if receipt.is_file():
            lines = receipt.read_text(encoding="utf-8").splitlines()
            if len(lines) >= 2 and lines[0].isdigit():
                port = int(lines[0])
                if 0 < port < 65536:
                    return port
        time.sleep(0.05)
    diagnostics = stderr_path.read_text(encoding="utf-8", errors="replace")
    raise TimeoutError(f"Chrome DevTools port was not published:\n{diagnostics}")


def _create_blank_target(port: int) -> str:
    """Create one about:blank target and return its local WebSocket URL."""
    request = Request(
        f"http://127.0.0.1:{port}/json/new?about:blank",
        method="PUT",
    )
    with urlopen(request, timeout=10) as response:  # noqa: S310 - fixed loopback
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("Chrome target response must be an object")
    websocket_url = payload.get("webSocketDebuggerUrl")
    if not isinstance(websocket_url, str):
        raise ValueError("Chrome target response omitted its WebSocket URL")
    return websocket_url


def _terminate_chrome(process: subprocess.Popen[bytes]) -> None:
    """Terminate the isolated Chrome process group within a finite bound."""
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


@contextmanager
def _chrome_client(chrome: Path) -> Iterator[_DevToolsWebSocket]:
    """Yield one isolated local Chrome DevTools client and remove its profile."""
    with tempfile.TemporaryDirectory() as profile_text:
        profile = Path(profile_text)
        stderr_path = profile / "chrome.stderr.log"
        with stderr_path.open("wb") as stderr_file:
            process = subprocess.Popen(  # noqa: S603 - workflow-owned binary
                [
                    str(chrome),
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--disable-extensions",
                    "--disable-sync",
                    "--metrics-recording-only",
                    "--no-first-run",
                    "--safebrowsing-disable-auto-update",
                    "--disable-features=MediaRouter,OptimizationHints,Translate",
                    f"--user-data-dir={profile}",
                    "--remote-debugging-port=0",
                    "about:blank",
                ],
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                start_new_session=True,
            )
        client: _DevToolsWebSocket | None = None
        try:
            port = _wait_for_debug_port(profile, process, stderr_path)
            client = _DevToolsWebSocket(_create_blank_target(port))
            yield client
        finally:
            if client is not None:
                client.close()
            _terminate_chrome(process)


def _evaluation_value(result: dict[str, Any]) -> Any:
    """Return one by-value Runtime.evaluate result and reject JS exceptions."""
    if "exceptionDetails" in result:
        raise AssertionError(f"Browser evaluation failed: {result['exceptionDetails']}")
    remote = result.get("result")
    if not isinstance(remote, dict) or "value" not in remote:
        raise AssertionError(f"Browser evaluation omitted a value: {result}")
    return remote["value"]


def test_hostile_scan_values_remain_inert_in_rendered_console() -> None:
    """Prove script and event-handler payloads stay text in list and detail DOM."""
    chrome = _chrome_path()
    with _chrome_client(chrome) as client:
        client.call("Runtime.enable")
        client.call("Page.enable")
        frame_tree = client.call("Page.getFrameTree")
        frame_id = frame_tree["frameTree"]["frame"]["id"]
        client.call(
            "Page.setDocumentContent",
            {
                "frameId": frame_id,
                "html": _instrumented_console(),
            },
        )

        deadline = time.monotonic() + 20
        rendered = False
        while time.monotonic() < deadline:
            result = client.call(
                "Runtime.evaluate",
                {
                    "expression": 'document.body?.dataset.testDone === "1"',
                    "returnByValue": True,
                },
            )
            if _evaluation_value(result) is True:
                rendered = True
                break
            time.sleep(0.1)
        assert rendered, "Chrome did not complete list and detail rendering"

        result = client.call(
            "Runtime.evaluate",
            {
                "expression": """(() => ({
  done: document.body?.dataset.testDone || null,
  failure: document.body?.dataset.testFailure || null,
  executed: document.body?.dataset.xssExecuted || null,
  imageNode: Boolean(document.getElementById("xss-image")),
  scriptNode: Boolean(document.getElementById("xss-script")),
  html: document.documentElement.outerHTML
}))()""",
                "returnByValue": True,
            },
        )
        evidence = _evaluation_value(result)

    assert isinstance(evidence, dict)
    assert evidence["done"] == "1"
    assert evidence["failure"] is None
    assert evidence["executed"] is None
    assert evidence["imageNode"] is False
    assert evidence["scriptNode"] is False
    assert "&lt;img" in evidence["html"]
    assert "&lt;script" in evidence["html"]
