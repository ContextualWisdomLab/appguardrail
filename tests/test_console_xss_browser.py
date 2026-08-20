"""Rendered-browser regression for the organization console DOM XSS boundary."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from typing import Iterator
from urllib.parse import urlsplit

import pytest

from scanner.cli.appguardrail import dashboard_index_path


_IMAGE_PAYLOAD = (
    '<img id="xss-image" src="/missing" '
    'onerror="document.body.dataset.xssExecuted=\'1\'">'
)
_SCRIPT_PAYLOAD = (
    '<script id="xss-script">'
    "document.body.dataset.xssExecuted='1'"
    "</script>"
)


def _instrumented_console() -> bytes:
    """Return the shipped console with a deterministic same-origin test driver."""
    source = (
        dashboard_index_path()
        .with_name("console.html")
        .read_text(encoding="utf-8")
    )
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
    return source.replace(marker, driver, 1).encode("utf-8")


class _ConsoleHandler(BaseHTTPRequestHandler):
    """Serve the instrumented console and bounded hostile JSON fixtures."""

    console_bytes = _instrumented_console()

    def _send(self, status: int, media_type: str, body: bytes) -> None:
        """Write one finite no-store response."""
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: object) -> None:
        """Serialize a JSON fixture with deterministic UTF-8 bytes."""
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(200, "application/json; charset=utf-8", body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        """Serve only the paths required by the rendered regression."""
        path = urlsplit(self.path).path
        if path == "/console.html":
            self._send(200, "text/html; charset=utf-8", self.console_bytes)
            return
        if path == "/api/v1/scans":
            self._send_json(
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
            return
        if path.startswith("/api/v1/scans/"):
            self._send_json(
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
            return
        self._send(404, "text/plain; charset=utf-8", b"not found")

    def log_message(self, _format: str, *_args: object) -> None:
        """Keep browser fixture requests out of test output."""


@contextmanager
def _console_server() -> Iterator[str]:
    """Run the bounded HTTP fixture server and yield its console URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ConsoleHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/console.html"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _chrome_path() -> Path:
    """Return the workflow-provisioned Chrome executable or skip locally."""
    value = os.environ.get("APPGUARDRAIL_CHROME_PATH")
    if not value:
        pytest.skip("rendered-browser lane provides APPGUARDRAIL_CHROME_PATH")
    path = Path(value)
    assert path.is_file(), f"Chrome executable does not exist: {path}"
    return path


def test_hostile_scan_values_remain_inert_in_rendered_console() -> None:
    """Prove script and event-handler payloads stay text in list and detail DOM."""
    chrome = _chrome_path()
    with _console_server() as url, tempfile.TemporaryDirectory() as profile:
        command = [
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
            "--virtual-time-budget=8000",
            "--dump-dom",
            url,
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired as error:
            pytest.fail(f"Chrome timed out before rendering the fixture: {error}")

    assert completed.returncode == 0, completed.stderr[-4000:]
    dom = completed.stdout
    assert 'data-test-done="1"' in dom
    assert "data-test-failure=" not in dom
    assert 'data-xss-executed="1"' not in dom
    assert '<img id="xss-image"' not in dom
    assert '<script id="xss-script"' not in dom
    assert "&lt;img" in dom
    assert "&lt;script" in dom
